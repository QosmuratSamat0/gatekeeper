package email

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"
)

// generateTestCert creates an ephemeral self-signed ECDSA certificate for testing TLS handshakes.
func generateTestCert(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsName},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(parsedCert)

	return cert, pool
}

func TestSMTPEmailSender_MandatorySTARTTLS_RejectedIfMissing(t *testing.T) {
	// Start mock SMTP server that does NOT advertise STARTTLS
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		tp := textproto.NewConn(conn)
		_ = tp.PrintfLine("220 mock.smtp service ready")
		line, _ := tp.ReadLine()
		if strings.HasPrefix(line, "EHLO") {
			_ = tp.PrintfLine("250-mock.smtp")
			_ = tp.PrintfLine("250 HELP") // No STARTTLS advertised
		}
	}()

	host, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	sender := &SMTPEmailSender{
		host:        host,
		port:        port,
		from:        "test@example.com",
		sendTimeout: 2 * time.Second,
	}

	err = sender.SendVerificationEmail(context.Background(), "user@example.com", "dummytoken123456789012345678901234567890123", time.Now().Add(time.Hour))
	if err == nil {
		t.Fatalf("expected error when server lacks STARTTLS, got nil")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected STARTTLS error, got: %v", err)
	}
}

func TestSMTPEmailSender_SuccessfulDeliveryWithTLSAndAuth(t *testing.T) {
	tlsCert, caPool := generateTestCert(t, "localhost")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	receivedData := make(chan string, 1)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		tp := textproto.NewConn(conn)

		_ = tp.PrintfLine("220 localhost ESMTP test")
		_, _ = tp.ReadLine() // EHLO

		_ = tp.PrintfLine("250-localhost")
		_ = tp.PrintfLine("250 STARTTLS")

		line, _ := tp.ReadLine() // STARTTLS
		if line != "STARTTLS" {
			return
		}
		_ = tp.PrintfLine("220 2.0.0 Ready to start TLS")

		// Upgrade server connection to TLS
		tlsServer := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		})
		if err := tlsServer.Handshake(); err != nil {
			return
		}
		defer func() { _ = tlsServer.Close() }()

		tlsTp := textproto.NewConn(tlsServer)
		_, _ = tlsTp.ReadLine() // EHLO after TLS

		_ = tlsTp.PrintfLine("250-localhost")
		_ = tlsTp.PrintfLine("250 AUTH PLAIN")

		_, _ = tlsTp.ReadLine() // AUTH PLAIN ...
		_ = tlsTp.PrintfLine("235 2.7.0 Authentication successful")

		_, _ = tlsTp.ReadLine() // MAIL FROM:...
		_ = tlsTp.PrintfLine("250 2.1.0 Ok")

		_, _ = tlsTp.ReadLine() // RCPT TO:...
		_ = tlsTp.PrintfLine("250 2.1.5 Ok")

		_, _ = tlsTp.ReadLine() // DATA
		_ = tlsTp.PrintfLine("354 End data with <CR><LF>.<CR><LF>")

		// Read email data until "."
		var bodyBuilder strings.Builder
		for {
			line, err := tlsTp.ReadLine()
			if err != nil || line == "." {
				break
			}
			bodyBuilder.WriteString(line + "\n")
		}
		_ = tlsTp.PrintfLine("250 2.0.0 Ok: queued")
		_, _ = tlsTp.ReadLine() // QUIT

		receivedData <- bodyBuilder.String()
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	sender := &SMTPEmailSender{
		host:        "localhost",
		port:        port,
		username:    "testuser",
		password:    "testpass",
		from:        "noreply@gatekeeper.local",
		caPool:      caPool,
		sendTimeout: 5 * time.Second,
	}

	testToken := "abcdefghijklmnopqrstuvwxyz01234567890123456"
	err = sender.SendVerificationEmail(context.Background(), "user@example.com", testToken, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("SendVerificationEmail failed: %v", err)
	}

	select {
	case body := <-receivedData:
		if !strings.Contains(body, testToken) {
			t.Fatalf("expected token in email body, got: %s", body)
		}
		if !strings.Contains(body, "Subject: Verify your email address") {
			t.Fatalf("expected Subject header, got: %s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for email data")
	}
}

func TestSMTPEmailSender_CertVerificationFailure_FailsClosed(t *testing.T) {
	// Generate certificate for "different-host"
	tlsCert, _ := generateTestCert(t, "different-host")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		tp := textproto.NewConn(conn)
		_ = tp.PrintfLine("220 localhost ESMTP test")
		_, _ = tp.ReadLine() // EHLO
		_ = tp.PrintfLine("250-localhost")
		_ = tp.PrintfLine("250 STARTTLS")

		_, _ = tp.ReadLine() // STARTTLS
		_ = tp.PrintfLine("220 Ready for TLS")

		tlsServer := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		})
		_ = tlsServer.Handshake()
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Sender expects "localhost", but server presents "different-host"
	sender := &SMTPEmailSender{
		host:        "localhost",
		port:        port,
		username:    "user",
		password:    "pass",
		from:        "noreply@example.com",
		sendTimeout: 2 * time.Second,
	}

	err = sender.SendVerificationEmail(context.Background(), "user@example.com", "token123", time.Now().Add(time.Hour))
	if err == nil {
		t.Fatalf("expected TLS certificate verification error, got nil")
	}
}

func TestSMTPEmailSender_TimeoutEnforced(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Server that accepts connection and hangs forever without sending 220 banner
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		time.Sleep(2 * time.Second)
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	sender := &SMTPEmailSender{
		host:        "127.0.0.1",
		port:        port,
		from:        "noreply@example.com",
		sendTimeout: 200 * time.Millisecond, // very short timeout
	}

	start := time.Now()
	err = sender.SendVerificationEmail(context.Background(), "user@example.com", "token", time.Now().Add(time.Hour))
	duration := time.Since(start)

	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if duration > 1*time.Second {
		t.Fatalf("expected operation to abort near 200ms, took %v", duration)
	}
}

func TestSMTPEmailSender_PasswordResetEmailDelivery(t *testing.T) {
	tlsCert, caPool := generateTestCert(t, "localhost")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	receivedData := make(chan string, 1)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		tp := textproto.NewConn(conn)

		_ = tp.PrintfLine("220 localhost ESMTP test")
		_, _ = tp.ReadLine() // EHLO

		_ = tp.PrintfLine("250-localhost")
		_ = tp.PrintfLine("250 STARTTLS")

		line, _ := tp.ReadLine() // STARTTLS
		if line != "STARTTLS" {
			return
		}
		_ = tp.PrintfLine("220 2.0.0 Ready to start TLS")

		tlsServer := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		})
		if err := tlsServer.Handshake(); err != nil {
			return
		}
		defer func() { _ = tlsServer.Close() }()

		tlsTp := textproto.NewConn(tlsServer)
		_, _ = tlsTp.ReadLine() // EHLO after TLS

		_ = tlsTp.PrintfLine("250-localhost")
		_ = tlsTp.PrintfLine("250 OK")

		_, _ = tlsTp.ReadLine() // MAIL FROM:...
		_ = tlsTp.PrintfLine("250 2.1.0 Ok")

		_, _ = tlsTp.ReadLine() // RCPT TO:...
		_ = tlsTp.PrintfLine("250 2.1.5 Ok")

		_, _ = tlsTp.ReadLine() // DATA
		_ = tlsTp.PrintfLine("354 End data with <CR><LF>.<CR><LF>")

		var bodyBuilder strings.Builder
		for {
			line, err := tlsTp.ReadLine()
			if err != nil || line == "." {
				break
			}
			bodyBuilder.WriteString(line + "\n")
		}
		_ = tlsTp.PrintfLine("250 2.0.0 Ok: queued")
		_, _ = tlsTp.ReadLine() // QUIT

		receivedData <- bodyBuilder.String()
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	sender := &SMTPEmailSender{
		host:        "localhost",
		port:        port,
		from:        "noreply@gatekeeper.local",
		caPool:      caPool,
		sendTimeout: 5 * time.Second,
	}

	testToken := "resettoken123456789012345678901234567890123"
	err = sender.SendPasswordResetEmail(context.Background(), "user@example.com", testToken, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("SendPasswordResetEmail failed: %v", err)
	}

	select {
	case body := <-receivedData:
		if !strings.Contains(body, testToken) {
			t.Fatalf("expected token in email body, got: %s", body)
		}
		if !strings.Contains(body, "Subject: Reset your password") {
			t.Fatalf("expected Subject header, got: %s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for email data")
	}
}

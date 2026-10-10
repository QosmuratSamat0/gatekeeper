package email

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrSTARTTLSNotSupported indicates the SMTP server does not advertise the STARTTLS extension.
	// We fail closed to prevent sending plaintext credentials or tokens over unencrypted channels.
	ErrSTARTTLSNotSupported = errors.New("smtp server does not support mandatory STARTTLS")
)

// SMTPConfig holds configuration for the SMTP adapter.
type SMTPConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	From        string
	CAFile      string
	SendTimeout time.Duration
}

// SMTPEmailSender implements usecase.EmailSender using Go standard library net/smtp.
type SMTPEmailSender struct {
	host        string
	port        int
	username    string
	password    string
	from        string
	caPool      *x509.CertPool
	sendTimeout time.Duration
}

// NewSMTPEmailSender creates an SMTPEmailSender with validated configuration.
// If caFile is provided, it loads custom root certificates into the TLS configuration.
func NewSMTPEmailSender(cfg SMTPConfig) (*SMTPEmailSender, error) {
	if cfg.Host == "" {
		return nil, errors.New("smtp host is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, errors.New("smtp port must be between 1 and 65535")
	}
	if cfg.From == "" {
		return nil, errors.New("smtp from address is required")
	}

	sendTimeout := cfg.SendTimeout
	if sendTimeout <= 0 {
		sendTimeout = 10 * time.Second
	}

	var caPool *x509.CertPool
	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading smtp ca file: %w", err)
		}
		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse certificates from smtp ca file %s", cfg.CAFile)
		}
	}

	return &SMTPEmailSender{
		host:        cfg.Host,
		port:        cfg.Port,
		username:    cfg.Username,
		password:    cfg.Password,
		from:        cfg.From,
		caPool:      caPool,
		sendTimeout: sendTimeout,
	}, nil
}

// SendVerificationEmail delivers a plain-text verification message containing the raw token.
// The entire SMTP sequence is strictly bounded by SendTimeout and context cancellation.
func (s *SMTPEmailSender) SendVerificationEmail(ctx context.Context, recipientEmail string, rawToken string, expiresAt time.Time) error {
	// Derive a strictly bounded context using the configured send timeout.
	// This ensures network I/O cannot hang indefinitely even if the caller passes an unbounded context.
	sendCtx, cancel := context.WithTimeout(ctx, s.sendTimeout)
	defer cancel()

	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))

	// Dial the SMTP server within the bounded context.
	var dialer net.Dialer
	conn, err := dialer.DialContext(sendCtx, "tcp", addr)
	if err != nil {
		if sendCtx.Err() != nil {
			return fmt.Errorf("smtp dial timed out: %w", sendCtx.Err())
		}
		return fmt.Errorf("smtp dial failed: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// Unconditionally set the network socket deadline to match the derived context deadline.
	// This provides a hardware/kernel socket timeout for all subsequent standard library operations.
	deadline, _ := sendCtx.Deadline()
	_ = conn.SetDeadline(deadline)

	// Actively monitor context cancellation to force-close the underlying socket.
	// Standard library net/smtp methods can block on slow or uncooperative servers;
	// closing the socket unblocks reading and writing immediately without leaking goroutines.
	stopWatcher := make(chan struct{})
	defer close(stopWatcher)
	go func() {
		select {
		case <-sendCtx.Done():
			_ = conn.Close()
		case <-stopWatcher:
		}
	}()

	// Initialize the SMTP client over the established connection.
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		if sendCtx.Err() != nil {
			return fmt.Errorf("smtp client init timed out: %w", sendCtx.Err())
		}
		return fmt.Errorf("smtp client init failed: %w", err)
	}
	defer client.Close() //nolint:errcheck

	// Verify that the server advertises STARTTLS.
	// Plaintext transmission is strictly forbidden to protect tokens and credentials in transit.
	hasSTARTTLS, _ := client.Extension("STARTTLS")
	if !hasSTARTTLS {
		return ErrSTARTTLSNotSupported
	}

	// Upgrade the connection to TLS with verified certificates.
	// InsecureSkipVerify is strictly false to prevent man-in-the-middle attacks.
	tlsConfig := &tls.Config{
		ServerName: s.host,
		MinVersion: tls.VersionTLS12,
		RootCAs:    s.caPool,
	}
	if err := client.StartTLS(tlsConfig); err != nil {
		if sendCtx.Err() != nil {
			return fmt.Errorf("smtp starttls timed out: %w", sendCtx.Err())
		}
		return fmt.Errorf("smtp starttls handshake failed: %w", err)
	}

	// Authenticate strictly after TLS establishment if credentials are configured.
	// Sending plaintext credentials before encryption would expose passwords over the network.
	if s.username != "" {
		auth := smtp.PlainAuth("", s.username, s.password, s.host)
		if err := client.Auth(auth); err != nil {
			if sendCtx.Err() != nil {
				return fmt.Errorf("smtp authentication timed out: %w", sendCtx.Err())
			}
			return fmt.Errorf("smtp authentication failed: %w", err)
		}
	}

	// Specify envelope sender.
	if err := client.Mail(s.from); err != nil {
		if sendCtx.Err() != nil {
			return fmt.Errorf("smtp mail command timed out: %w", sendCtx.Err())
		}
		return fmt.Errorf("smtp mail command failed: %w", err)
	}

	// Specify envelope recipient.
	if err := client.Rcpt(recipientEmail); err != nil {
		if sendCtx.Err() != nil {
			return fmt.Errorf("smtp rcpt command timed out: %w", sendCtx.Err())
		}
		return fmt.Errorf("smtp rcpt command failed: %w", err)
	}

	// Initiate email data transfer.
	w, err := client.Data()
	if err != nil {
		if sendCtx.Err() != nil {
			return fmt.Errorf("smtp data command timed out: %w", sendCtx.Err())
		}
		return fmt.Errorf("smtp data command failed: %w", err)
	}

	// Construct and send the plain-text message.
	// Do not include tokens in URLs or query strings.
	body := buildPlainTextEmail(s.from, recipientEmail, rawToken, expiresAt)
	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		if sendCtx.Err() != nil {
			return fmt.Errorf("smtp message write timed out: %w", sendCtx.Err())
		}
		return fmt.Errorf("smtp message write failed: %w", err)
	}

	if err := w.Close(); err != nil {
		if sendCtx.Err() != nil {
			return fmt.Errorf("smtp message close timed out: %w", sendCtx.Err())
		}
		return fmt.Errorf("smtp message close failed: %w", err)
	}

	_ = client.Quit()
	return nil
}

func buildPlainTextEmail(from, to, token string, expiresAt time.Time) []byte {
	headers := []string{
		"From: " + from,
		"To: " + to,
		"Subject: Verify your email address",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
	}

	content := []string{
		"Please use the following verification token to verify your email address:",
		"",
		token,
		"",
		"This token will expire at " + expiresAt.UTC().Format(time.RFC3339) + ".",
		"If you did not request this email, no action is required.",
	}

	return []byte(strings.Join(headers, "\r\n") + "\r\n" + strings.Join(content, "\r\n") + "\r\n")
}

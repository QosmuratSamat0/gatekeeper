package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Default Argon2id parameters per AUTH-01 specification.
const (
	DefaultMemory      uint32 = 64 * 1024 // 65536 KiB (64 MiB)
	DefaultIterations  uint32 = 3
	DefaultParallelism uint8  = 1
	DefaultSaltLength  uint32 = 16
	DefaultKeyLength   uint32 = 32
)

// Argon2idHasher implements usecase.PasswordHasher with bounded concurrency.
// Each password hash uses about 64 MiB of memory and hundreds of milliseconds of CPU.
// The concurrency semaphore limits simultaneous calculations so spikes in registration
// traffic cannot exhaust the server's memory.
type Argon2idHasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
	sem         chan struct{}

	// Optional hooks for observing real concurrency in unit tests.
	onStart func()
	onDone  func()
}

// NewArgon2idHasher creates a hasher with the specified concurrency limit and default Argon2id parameters.
func NewArgon2idHasher(concurrency int) *Argon2idHasher {
	if concurrency <= 0 {
		concurrency = 2
	}
	return &Argon2idHasher{
		memory:      DefaultMemory,
		iterations:  DefaultIterations,
		parallelism: DefaultParallelism,
		saltLength:  DefaultSaltLength,
		keyLength:   DefaultKeyLength,
		sem:         make(chan struct{}, concurrency),
	}
}

// NewArgon2idHasherWithParams creates a hasher with custom parameters (useful for fast unit tests).
func NewArgon2idHasherWithParams(memory uint32, iterations uint32, parallelism uint8, saltLength, keyLength uint32, concurrency int) *Argon2idHasher {
	if concurrency <= 0 {
		concurrency = 2
	}
	return &Argon2idHasher{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		saltLength:  saltLength,
		keyLength:   keyLength,
		sem:         make(chan struct{}, concurrency),
	}
}

// SetObserver attaches hooks that fire when a hashing calculation begins and finishes.
// This allows tests to observe actual concurrency without altering cryptographic code.
func (h *Argon2idHasher) SetObserver(onStart, onDone func()) {
	h.onStart = onStart
	h.onDone = onDone
}

// Hash produces a PHC-formatted Argon2id hash string.
// Waiting for a slot respects context cancellation: if a client aborts or times out
// before or while waiting in the queue, we return immediately without computing the expensive hash.
// Go's select statement chooses pseudo-randomly when multiple channels are ready;
// therefore, we check ctx.Err() before waiting and immediately after acquiring the slot.
// Once the calculation begins, Argon2 cannot be interrupted mid-loop, so the slot
// remains held until computation completes.
func (h *Argon2idHasher) Hash(ctx context.Context, password string) (string, error) {
	// 1. Fast path: abort immediately if context was already cancelled before entering queue.
	if err := ctx.Err(); err != nil {
		return "", err
	}

	select {
	case h.sem <- struct{}{}:
		// 2. Check context immediately after acquiring the slot.
		// If context expired right as the slot became available, release it instantly
		// so other pending callers can proceed without wasting CPU/memory.
		if err := ctx.Err(); err != nil {
			<-h.sem
			return "", err
		}
		defer func() {
			if h.onDone != nil {
				h.onDone()
			}
			<-h.sem
		}()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	if h.onStart != nil {
		h.onStart()
	}

	salt := make([]byte, h.saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate random salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, h.iterations, h.memory, h.parallelism, h.keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.iterations, h.parallelism, b64Salt, b64Hash)

	return encoded, nil
}

// Verify parses a PHC-formatted Argon2id hash and verifies a candidate password against it.
// It enforces that the hash parameters exactly match the hasher's configured parameters
// (defaulting to 64 MiB memory, 3 iterations, 1 parallelism, 16-byte salt, 32-byte key),
// rejecting any deviations before allocating memory.
// It shares the exact same concurrency semaphore as Hash to ensure the overall memory budget is respected.
func (h *Argon2idHasher) Verify(ctx context.Context, password string, phcHash string) (bool, error) {
	salt, expectedHash, err := h.parseAndValidatePHC(phcHash)
	if err != nil {
		return false, fmt.Errorf("parsing argon2id hash: %w", err)
	}

	// Fast path: abort immediately if context was already cancelled before acquiring semaphore.
	if err := ctx.Err(); err != nil {
		return false, err
	}

	select {
	case h.sem <- struct{}{}:
		// Verify context immediately after acquiring slot.
		if err := ctx.Err(); err != nil {
			<-h.sem
			return false, err
		}
		defer func() {
			if h.onDone != nil {
				h.onDone()
			}
			<-h.sem
		}()
	case <-ctx.Done():
		return false, ctx.Err()
	}

	if h.onStart != nil {
		h.onStart()
	}

	computed := argon2.IDKey([]byte(password), salt, h.iterations, h.memory, h.parallelism, h.keyLength)

	// Constant-time comparison prevents timing side-channels from leaking hash bytes.
	match := subtle.ConstantTimeCompare(computed, expectedHash) == 1
	return match, nil
}

// parseAndValidatePHC strictly parses and validates the PHC string structure and parameters.
// Any malformed format, unsupported algorithm/version, or parameter mismatch is rejected upfront.
func (h *Argon2idHasher) parseAndValidatePHC(phcHash string) ([]byte, []byte, error) {
	// Expected format: $argon2id$v=19$m=65536,t=3,p=1$<b64Salt>$<b64Hash>
	if !strings.HasPrefix(phcHash, "$argon2id$") {
		return nil, nil, fmt.Errorf("unsupported algorithm identifier")
	}

	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 {
		return nil, nil, fmt.Errorf("invalid phc format structure: expected 6 parts, got %d", len(parts))
	}

	// parts[0] is empty (due to leading '$')
	// parts[1] is "argon2id"
	// parts[2] is version "v=19"
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, nil, fmt.Errorf("unsupported argon2 version: %s", parts[2])
	}

	// parts[3] is parameters "m=...,t=...,p=..."
	var mem, iter uint32
	var parallel uint8
	paramPairs := strings.Split(parts[3], ",")
	if len(paramPairs) != 3 {
		return nil, nil, fmt.Errorf("invalid parameter count in phc: %s", parts[3])
	}

	for _, pair := range paramPairs {
		kv := strings.Split(pair, "=")
		if len(kv) != 2 {
			return nil, nil, fmt.Errorf("invalid parameter pair: %s", pair)
		}
		val, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid parameter value in %s: %w", pair, err)
		}
		switch kv[0] {
		case "m":
			mem = uint32(val)
		case "t":
			iter = uint32(val)
		case "p":
			if val > 255 {
				return nil, nil, fmt.Errorf("parallelism parameter exceeds uint8: %d", val)
			}
			parallel = uint8(val)
		default:
			return nil, nil, fmt.Errorf("unknown parameter key: %s", kv[0])
		}
	}

	// Enforce exact match with the hasher's configured parameters.
	// This prevents memory exhaustion from hashes crafted with excessive memory parameters.
	if mem != h.memory || iter != h.iterations || parallel != h.parallelism {
		return nil, nil, fmt.Errorf("unsupported or mismatched argon2id parameters (m=%d, t=%d, p=%d)", mem, iter, parallel)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64 salt: %w", err)
	}
	if uint32(len(salt)) != h.saltLength {
		return nil, nil, fmt.Errorf("unexpected salt length: got %d, expected %d", len(salt), h.saltLength)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64 hash: %w", err)
	}
	if uint32(len(expectedHash)) != h.keyLength {
		return nil, nil, fmt.Errorf("unexpected hash length: got %d, expected %d", len(expectedHash), h.keyLength)
	}

	return salt, expectedHash, nil
}

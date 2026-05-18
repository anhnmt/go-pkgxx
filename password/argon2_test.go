package password

import (
	"strings"
	"testing"
)

func TestNewArgon2Hasher_Algorithm(t *testing.T) {
	tests := []struct {
		name string
		want Algorithm
	}{
		{
			name: "returns AlgorithmArgon2",
			want: AlgorithmArgon2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewArgon2Hasher()
			if got := h.Algorithm(); got != tt.want {
				t.Errorf("Algorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewArgon2Hasher_DefaultParams(t *testing.T) {
	tests := []struct {
		name        string
		wantMemory  uint32
		wantTime    uint32
		wantThreads uint8
	}{
		{
			name:        "default params match RFC recommendations",
			wantMemory:  64 * 1024,
			wantTime:    3,
			wantThreads: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewArgon2Hasher().(*argon2Hasher)
			if h.cfg.MemoryCost != tt.wantMemory {
				t.Errorf("MemoryCost = %v, want %v", h.cfg.MemoryCost, tt.wantMemory)
			}
			if h.cfg.TimeCost != tt.wantTime {
				t.Errorf("TimeCost = %v, want %v", h.cfg.TimeCost, tt.wantTime)
			}
			if h.cfg.Parallelism != tt.wantThreads {
				t.Errorf("Parallelism = %v, want %v", h.cfg.Parallelism, tt.wantThreads)
			}
		})
	}
}

func TestNewArgon2Hasher_CustomOptions(t *testing.T) {
	type args struct {
		memory  uint32
		time    uint32
		threads uint8
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "custom memory time threads are applied",
			args: args{memory: 32 * 1024, time: 2, threads: 4},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewArgon2Hasher(
				WithMemory(tt.args.memory),
				WithTime(tt.args.time),
				WithThreads(tt.args.threads),
			).(*argon2Hasher)
			if h.cfg.MemoryCost != tt.args.memory {
				t.Errorf("MemoryCost = %v, want %v", h.cfg.MemoryCost, tt.args.memory)
			}
			if h.cfg.TimeCost != tt.args.time {
				t.Errorf("TimeCost = %v, want %v", h.cfg.TimeCost, tt.args.time)
			}
			if h.cfg.Parallelism != tt.args.threads {
				t.Errorf("Parallelism = %v, want %v", h.cfg.Parallelism, tt.args.threads)
			}
		})
	}
}

func TestArgon2Hasher_Hash(t *testing.T) {
	type args struct {
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "valid password returns argon2id PHC hash",
			args:    args{password: "securePassword1!"},
			wantErr: nil,
		},
		{
			name:    "empty password returns ErrPasswordEmpty",
			args:    args{password: ""},
			wantErr: ErrPasswordEmpty,
		},
		{
			name:    "password too short returns ErrPasswordTooShort",
			args:    args{password: "short"},
			wantErr: ErrPasswordTooShort,
		},
		{
			name:    "password too long returns ErrPasswordTooLong",
			args:    args{password: strings.Repeat("a", 73)},
			wantErr: ErrPasswordTooLong,
		},
		{
			name:    "password at exact min length is valid",
			args:    args{password: "12345678"},
			wantErr: nil,
		},
		{
			name:    "password at exact max length is valid",
			args:    args{password: strings.Repeat("a", 72)},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewArgon2Hasher()
			got, err := h.Hash(tt.args.password)
			if err != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil {
				if got == "" {
					t.Errorf("Hash() returned empty string for valid password")
				}
				if IdentifyAlgorithm(got) != AlgorithmArgon2 {
					t.Errorf("Hash() output not recognized as argon2: %q", got)
				}
				// Ensure no trailing whitespace that would break VerifyEncoded.
				if got != strings.TrimSpace(got) {
					t.Errorf("Hash() returned string with leading/trailing whitespace: %q", got)
				}
			}
		})
	}
}

func TestArgon2Hasher_HashIsNonDeterministic(t *testing.T) {
	type args struct {
		password string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "two hashes of same password differ due to random salt",
			args: args{password: "samePassword1!"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewArgon2Hasher()
			hash1, _ := h.Hash(tt.args.password)
			hash2, _ := h.Hash(tt.args.password)
			if hash1 == hash2 {
				t.Errorf("Hash() produced identical hashes — salt may not be random")
			}
		})
	}
}

func TestArgon2Hasher_Compare(t *testing.T) {
	h := NewArgon2Hasher()
	validPassword := "securePassword1!"

	validHash, err := h.Hash(validPassword)
	if err != nil {
		t.Fatalf("Hash() setup failed: %v", err)
	}
	bcryptHash, _ := NewBcryptHasher().Hash(validPassword)

	type args struct {
		password string
		hash     string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "correct password matches hash",
			args: args{password: validPassword, hash: validHash},
			want: true,
		},
		{
			name: "wrong password does not match",
			args: args{password: "wrongPassword!", hash: validHash},
			want: false,
		},
		{
			name: "algorithm mismatch with bcrypt hash returns false",
			args: args{password: validPassword, hash: bcryptHash},
			want: false,
		},
		{
			name: "malformed argon2 hash returns false",
			args: args{password: validPassword, hash: "$argon2id$v=19$m=65536,t=3,p=2$broken"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := h.Compare(tt.args.password, tt.args.hash); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestArgon2Hasher_Compare_EmptyHash isolates the empty-hash edge case because
// IdentifyAlgorithm in password.go has an operator-precedence bug:
//
//	// BUG: hash[:4] == "$2b$" is evaluated without the len guard → panic on ""
//	len(hash) > 4 && hash[:4] == "$2a$" || hash[:4] == "$2b$"
//
//	// FIX in password.go line 102:
//	len(hash) > 4 && (hash[:4] == "$2a$" || hash[:4] == "$2b$")
//
// The defer/recover here prevents the panic from crashing the entire test binary
// and reports it as a clear FAIL instead.
func TestArgon2Hasher_Compare_EmptyHash(t *testing.T) {
	h := NewArgon2Hasher()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Compare() panicked on empty hash — fix IdentifyAlgorithm in password.go:102 "+
				"by adding parentheses: (hash[:4] == \"$2a$\" || hash[:4] == \"$2b$\"). panic: %v", r)
		}
	}()

	if got := h.Compare("securePassword1!", ""); got != false {
		t.Errorf("Compare() = %v, want false", got)
	}
}

func TestArgon2Hasher_CustomLengthBounds(t *testing.T) {
	type args struct {
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "password within custom bounds is accepted",
			args:    args{password: "hello"},
			wantErr: nil,
		},
		{
			name:    "password below custom min returns ErrPasswordTooShort",
			args:    args{password: "hi"},
			wantErr: ErrPasswordTooShort,
		},
		{
			name:    "password above custom max returns ErrPasswordTooLong",
			args:    args{password: strings.Repeat("a", 21)},
			wantErr: ErrPasswordTooLong,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewArgon2Hasher(WithMinLength(3), WithMaxLength(20))
			_, err := h.Hash(tt.args.password)
			if err != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

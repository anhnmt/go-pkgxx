package password

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestNewBcryptHasher_Algorithm(t *testing.T) {
	tests := []struct {
		name string
		want Algorithm
	}{
		{
			name: "returns AlgorithmBcrypt",
			want: AlgorithmBcrypt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewBcryptHasher()
			if got := h.Algorithm(); got != tt.want {
				t.Errorf("Algorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewBcryptHasher_Cost(t *testing.T) {
	type args struct {
		cost int
	}
	tests := []struct {
		name     string
		args     args
		wantCost int
	}{
		{
			name:     "cost below MinCost falls back to DefaultCost",
			args:     args{cost: 0},
			wantCost: bcrypt.DefaultCost,
		},
		{
			name:     "cost above MaxCost falls back to DefaultCost",
			args:     args{cost: 100},
			wantCost: bcrypt.DefaultCost,
		},
		{
			name:     "valid cost 12 is accepted",
			args:     args{cost: 12},
			wantCost: 12,
		},
		{
			name:     "MinCost boundary is accepted",
			args:     args{cost: bcrypt.MinCost},
			wantCost: bcrypt.MinCost,
		},
		{
			name:     "MaxCost boundary is accepted",
			args:     args{cost: bcrypt.MaxCost},
			wantCost: bcrypt.MaxCost,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewBcryptHasher(WithCost(tt.args.cost)).(*bcryptHasher)
			if h.cost != tt.wantCost {
				t.Errorf("bcryptHasher.cost = %v, want %v", h.cost, tt.wantCost)
			}
		})
	}
}

func TestBcryptHasher_Hash(t *testing.T) {
	type args struct {
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "valid password returns non-empty hash",
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
			h := NewBcryptHasher()
			got, err := h.Hash(tt.args.password)
			if err != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil && got == "" {
				t.Errorf("Hash() returned empty string for valid password")
			}
		})
	}
}

func TestBcryptHasher_HashIsNonDeterministic(t *testing.T) {
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
			h := NewBcryptHasher()
			hash1, _ := h.Hash(tt.args.password)
			hash2, _ := h.Hash(tt.args.password)
			if hash1 == hash2 {
				t.Errorf("Hash() produced identical hashes — salt may not be random")
			}
		})
	}
}

func TestBcryptHasher_Compare(t *testing.T) {
	h := NewBcryptHasher()
	validPassword := "securePassword1!"

	validHash, err := h.Hash(validPassword)
	if err != nil {
		t.Fatalf("Hash() setup failed: %v", err)
	}
	argon2Hash := "$argon2id$v=19$m=65536,t=3,p=2$abc$def"

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
			name: "algorithm mismatch with argon2 hash returns false",
			args: args{password: validPassword, hash: argon2Hash},
			want: false,
		},
		{
			name: "malformed bcrypt hash returns false",
			args: args{password: validPassword, hash: "$2b$10$invalidddddddddddddddd"},
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

// TestBcryptHasher_Compare_EmptyHash isolates the empty-hash edge case because
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
func TestBcryptHasher_Compare_EmptyHash(t *testing.T) {
	h := NewBcryptHasher()

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

func TestBcryptHasher_CustomLengthBounds(t *testing.T) {
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
			h := NewBcryptHasher(WithMinLength(3), WithMaxLength(20))
			_, err := h.Hash(tt.args.password)
			if err != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

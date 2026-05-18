package password

import (
	"strings"
	"testing"
)

func TestIdentifyAlgorithm(t *testing.T) {
	type args struct {
		hash string
	}
	tests := []struct {
		name string
		args args
		want Algorithm
	}{
		{
			name: "bcrypt $2a$ prefix",
			args: args{hash: "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
			want: AlgorithmBcrypt,
		},
		{
			name: "bcrypt $2b$ prefix",
			args: args{hash: "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
			want: AlgorithmBcrypt,
		},
		{
			name: "argon2id prefix",
			args: args{hash: "$argon2id$v=19$m=65536,t=3,p=2$abc$def"},
			want: AlgorithmArgon2,
		},
		{
			name: "unknown prefix returns empty",
			args: args{hash: "$scrypt$something"},
			want: "",
		},
		{
			name: "empty string returns empty",
			args: args{hash: ""},
			want: "",
		},
		{
			name: "short string under 4 chars returns empty",
			args: args{hash: "$2a"},
			want: "",
		},
		{
			name: "short string under 9 chars for argon2id returns empty",
			args: args{hash: "$argon2"},
			want: "",
		},
		{
			name: "plaintext password returns empty",
			args: args{hash: "hunter2"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IdentifyAlgorithm(tt.args.hash); got != tt.want {
				t.Errorf("IdentifyAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	type args struct {
		password string
		min      int
		max      int
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "valid password within bounds",
			args:    args{password: "password123", min: 8, max: 72},
			wantErr: nil,
		},
		{
			name:    "empty password returns ErrPasswordEmpty",
			args:    args{password: "", min: 8, max: 72},
			wantErr: ErrPasswordEmpty,
		},
		{
			name:    "password too short returns ErrPasswordTooShort",
			args:    args{password: "abc", min: 8, max: 72},
			wantErr: ErrPasswordTooShort,
		},
		{
			name:    "password too long returns ErrPasswordTooLong",
			args:    args{password: strings.Repeat("a", 73), min: 8, max: 72},
			wantErr: ErrPasswordTooLong,
		},
		{
			name:    "password exactly at min boundary is valid",
			args:    args{password: "abcdefgh", min: 8, max: 72},
			wantErr: nil,
		},
		{
			name:    "password exactly at max boundary is valid",
			args:    args{password: strings.Repeat("a", 72), min: 8, max: 72},
			wantErr: nil,
		},
		{
			name:    "min length 1 and single char is valid",
			args:    args{password: "x", min: 1, max: 100},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.args.password, tt.args.min, tt.args.max)
			if err != tt.wantErr {
				t.Errorf("validatePassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	tests := []struct {
		name          string
		wantMinLength int
		wantMaxLength int
	}{
		{
			name:          "default config has min=8 max=72",
			wantMinLength: 8,
			wantMaxLength: 72,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			if cfg.MinLength != tt.wantMinLength {
				t.Errorf("defaultConfig().MinLength = %v, want %v", cfg.MinLength, tt.wantMinLength)
			}
			if cfg.MaxLength != tt.wantMaxLength {
				t.Errorf("defaultConfig().MaxLength = %v, want %v", cfg.MaxLength, tt.wantMaxLength)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	tests := []struct {
		name    string
		opt     Option
		verify  func(c *Config) bool
		wantVal string
	}{
		{
			name:    "WithCost sets Cost",
			opt:     WithCost(14),
			verify:  func(c *Config) bool { return c.Cost == 14 },
			wantVal: "Cost=14",
		},
		{
			name:    "WithMemory sets Memory",
			opt:     WithMemory(128 * 1024),
			verify:  func(c *Config) bool { return c.Memory == 128*1024 },
			wantVal: "Memory=131072",
		},
		{
			name:    "WithTime sets Time",
			opt:     WithTime(5),
			verify:  func(c *Config) bool { return c.Time == 5 },
			wantVal: "Time=5",
		},
		{
			name:    "WithThreads sets Threads",
			opt:     WithThreads(4),
			verify:  func(c *Config) bool { return c.Threads == 4 },
			wantVal: "Threads=4",
		},
		{
			name:    "WithMinLength sets MinLength",
			opt:     WithMinLength(10),
			verify:  func(c *Config) bool { return c.MinLength == 10 },
			wantVal: "MinLength=10",
		},
		{
			name:    "WithMaxLength sets MaxLength",
			opt:     WithMaxLength(128),
			verify:  func(c *Config) bool { return c.MaxLength == 128 },
			wantVal: "MaxLength=128",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			tt.opt(cfg)
			if !tt.verify(cfg) {
				t.Errorf("Option did not apply expected value: %s", tt.wantVal)
			}
		})
	}
}

func TestHasherInterface_CrossAlgorithmCompare(t *testing.T) {
	password := "crossCheckPass1!"

	bHasher := NewBcryptHasher()
	aHasher := NewArgon2Hasher()

	bcryptHash, _ := bHasher.Hash(password)
	argon2Hash, _ := aHasher.Hash(password)

	type args struct {
		hasher   Hasher
		password string
		hash     string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "bcrypt hasher rejects argon2 hash",
			args: args{hasher: bHasher, password: password, hash: argon2Hash},
			want: false,
		},
		{
			name: "argon2 hasher rejects bcrypt hash",
			args: args{hasher: aHasher, password: password, hash: bcryptHash},
			want: false,
		},
		{
			name: "bcrypt hasher accepts its own hash",
			args: args{hasher: bHasher, password: password, hash: bcryptHash},
			want: true,
		},
		{
			name: "argon2 hasher accepts its own hash",
			args: args{hasher: aHasher, password: password, hash: argon2Hash},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.args.hasher.Compare(tt.args.password, tt.args.hash); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasherInterface_AlgorithmIdentity(t *testing.T) {
	tests := []struct {
		name   string
		hasher Hasher
		want   Algorithm
	}{
		{
			name:   "bcrypt hasher reports AlgorithmBcrypt",
			hasher: NewBcryptHasher(),
			want:   AlgorithmBcrypt,
		},
		{
			name:   "argon2 hasher reports AlgorithmArgon2",
			hasher: NewArgon2Hasher(),
			want:   AlgorithmArgon2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hasher.Algorithm(); got != tt.want {
				t.Errorf("Algorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasherInterface_HashOutputIdentifiedByAlgorithm(t *testing.T) {
	password := "validPassword1!"

	tests := []struct {
		name     string
		hasher   Hasher
		wantAlgo Algorithm
	}{
		{
			name:     "bcrypt hash is identified as bcrypt",
			hasher:   NewBcryptHasher(),
			wantAlgo: AlgorithmBcrypt,
		},
		{
			name:     "argon2 hash is identified as argon2",
			hasher:   NewArgon2Hasher(),
			wantAlgo: AlgorithmArgon2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := tt.hasher.Hash(password)
			if err != nil {
				t.Fatalf("Hash() unexpected error: %v", err)
			}
			if got := IdentifyAlgorithm(hash); got != tt.wantAlgo {
				t.Errorf("IdentifyAlgorithm() = %v, want %v", got, tt.wantAlgo)
			}
		})
	}
}

package token_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/anhnmt/go-authxx/token"
)

// ── helpers ───────────────────────────────────────────────────────────────────

const testSecret = "super-secret-key-that-is-long-enough-32"

func mustMaker(t *testing.T, opts ...token.Option) *token.JWTMaker {
	t.Helper()
	m, err := token.NewJWTMaker(testSecret, opts...)
	if err != nil {
		t.Fatalf("NewJWTMaker: %v", err)
	}
	return m
}

func accessPayload() token.TokenPayload {
	return token.TokenPayload{
		UserID:       uuid.New(),
		SessionID:    uuid.New(),
		TokenID:      uuid.New(),
		Type:         token.AccessToken,
		TokenVersion: 1,
	}
}

func refreshPayload() token.TokenPayload {
	p := accessPayload()
	p.Type = token.RefreshToken
	return p
}

func mustSign(t *testing.T, m *token.JWTMaker, p token.TokenPayload) string {
	t.Helper()
	s, err := m.CreateToken(time.Now(), p)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	return s
}

func assertPayloadEqual(t *testing.T, want token.TokenPayload, got *token.TokenPayload) {
	t.Helper()
	if got.UserID != want.UserID {
		t.Errorf("UserID: want %v, got %v", want.UserID, got.UserID)
	}
	if got.SessionID != want.SessionID {
		t.Errorf("SessionID: want %v, got %v", want.SessionID, got.SessionID)
	}
	if got.TokenID != want.TokenID {
		t.Errorf("TokenID: want %v, got %v", want.TokenID, got.TokenID)
	}
	if got.Type != want.Type {
		t.Errorf("Type: want %v, got %v", want.Type, got.Type)
	}
	if got.TokenVersion != want.TokenVersion {
		t.Errorf("TokenVersion: want %v, got %v", want.TokenVersion, got.TokenVersion)
	}
}

// ── NewJWTMaker ───────────────────────────────────────────────────────────────

func TestNewJWTMaker_SecretValidation(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{
			name:    "empty secret is rejected",
			secret:  "",
			wantErr: true,
		},
		{
			name:    "8 byte secret is rejected",
			secret:  "tooshort",
			wantErr: true,
		},
		{
			name:    "31 byte secret is rejected",
			secret:  "exactly-31-bytes-of-padding-her",
			wantErr: true,
		},
		{
			name:    "32 byte secret is accepted",
			secret:  strings.Repeat("a", 32),
			wantErr: false,
		},
		{
			name:    "64 byte secret is accepted",
			secret:  strings.Repeat("a", 64),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := token.NewJWTMaker(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewJWTMaker() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewJWTMaker_DefaultTTLs(t *testing.T) {
	tests := []struct {
		name           string
		wantAccessTTL  time.Duration
		wantRefreshTTL time.Duration
	}{
		{
			name:           "defaults are 15m access and 7d refresh",
			wantAccessTTL:  15 * time.Minute,
			wantRefreshTTL: 7 * 24 * time.Hour,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mustMaker(t)
			if m.AccessTokenTTL() != tt.wantAccessTTL {
				t.Errorf("AccessTokenTTL() = %s, want %s", m.AccessTokenTTL(), tt.wantAccessTTL)
			}
			if m.RefreshTokenTTL() != tt.wantRefreshTTL {
				t.Errorf("RefreshTokenTTL() = %s, want %s", m.RefreshTokenTTL(), tt.wantRefreshTTL)
			}
		})
	}
}

// ── Options ───────────────────────────────────────────────────────────────────

func TestWithAccessTokenTTL(t *testing.T) {
	tests := []struct {
		name    string
		ttl     time.Duration
		wantErr bool
		wantTTL time.Duration
	}{
		{
			name:    "zero TTL is rejected",
			ttl:     0,
			wantErr: true,
		},
		{
			name:    "negative TTL is rejected",
			ttl:     -time.Minute,
			wantErr: true,
		},
		{
			name:    "positive TTL is accepted",
			ttl:     30 * time.Minute,
			wantErr: false,
			wantTTL: 30 * time.Minute,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := token.NewJWTMaker(testSecret, token.WithAccessTokenTTL(tt.ttl))
			if (err != nil) != tt.wantErr {
				t.Errorf("WithAccessTokenTTL(%s) error = %v, wantErr = %v", tt.ttl, err, tt.wantErr)
			}
			if err == nil && m.AccessTokenTTL() != tt.wantTTL {
				t.Errorf("AccessTokenTTL() = %s, want %s", m.AccessTokenTTL(), tt.wantTTL)
			}
		})
	}
}

func TestWithRefreshTokenTTL(t *testing.T) {
	tests := []struct {
		name    string
		ttl     time.Duration
		wantErr bool
		wantTTL time.Duration
	}{
		{
			name:    "zero TTL is rejected",
			ttl:     0,
			wantErr: true,
		},
		{
			name:    "negative TTL is rejected",
			ttl:     -time.Hour,
			wantErr: true,
		},
		{
			name:    "positive TTL is accepted",
			ttl:     24 * time.Hour,
			wantErr: false,
			wantTTL: 24 * time.Hour,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := token.NewJWTMaker(testSecret, token.WithRefreshTokenTTL(tt.ttl))
			if (err != nil) != tt.wantErr {
				t.Errorf("WithRefreshTokenTTL(%s) error = %v, wantErr = %v", tt.ttl, err, tt.wantErr)
			}
			if err == nil && m.RefreshTokenTTL() != tt.wantTTL {
				t.Errorf("RefreshTokenTTL() = %s, want %s", m.RefreshTokenTTL(), tt.wantTTL)
			}
		})
	}
}

func TestNewJWTMaker_BothTTLOptions(t *testing.T) {
	tests := []struct {
		name           string
		accessTTL      time.Duration
		refreshTTL     time.Duration
		wantAccessTTL  time.Duration
		wantRefreshTTL time.Duration
	}{
		{
			name:           "both TTLs are overridden",
			accessTTL:      10 * time.Minute,
			refreshTTL:     30 * 24 * time.Hour,
			wantAccessTTL:  10 * time.Minute,
			wantRefreshTTL: 30 * 24 * time.Hour,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mustMaker(t,
				token.WithAccessTokenTTL(tt.accessTTL),
				token.WithRefreshTokenTTL(tt.refreshTTL),
			)
			if m.AccessTokenTTL() != tt.wantAccessTTL {
				t.Errorf("AccessTokenTTL() = %s, want %s", m.AccessTokenTTL(), tt.wantAccessTTL)
			}
			if m.RefreshTokenTTL() != tt.wantRefreshTTL {
				t.Errorf("RefreshTokenTTL() = %s, want %s", m.RefreshTokenTTL(), tt.wantRefreshTTL)
			}
		})
	}
}

// ── CreateToken ───────────────────────────────────────────────────────────────

func TestCreateToken_Output(t *testing.T) {
	m := mustMaker(t)
	now := time.Now()

	tests := []struct {
		name      string
		payload   token.TokenPayload
		wantEmpty bool
	}{
		{
			name:      "access token produces non-empty string",
			payload:   accessPayload(),
			wantEmpty: false,
		},
		{
			name:      "refresh token produces non-empty string",
			payload:   refreshPayload(),
			wantEmpty: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.CreateToken(now, tt.payload)
			if err != nil {
				t.Fatalf("CreateToken() unexpected error: %v", err)
			}
			if (got == "") != tt.wantEmpty {
				t.Errorf("CreateToken() empty = %v, wantEmpty = %v", got == "", tt.wantEmpty)
			}
		})
	}
}

func TestCreateToken_TTLResolution(t *testing.T) {
	const drift = 2 * time.Second

	tests := []struct {
		name    string
		opts    []token.Option
		payload func() token.TokenPayload
		wantTTL time.Duration
	}{
		{
			name: "payload TTL takes precedence over maker default",
			payload: func() token.TokenPayload {
				p := accessPayload()
				p.TTL = 5 * time.Minute
				return p
			},
			wantTTL: 5 * time.Minute,
		},
		{
			name: "zero payload TTL falls back to maker access default",
			opts: []token.Option{token.WithAccessTokenTTL(10 * time.Minute)},
			payload: func() token.TokenPayload {
				p := accessPayload()
				p.TTL = 0
				return p
			},
			wantTTL: 10 * time.Minute,
		},
		{
			name: "zero payload TTL falls back to maker refresh default",
			opts: []token.Option{token.WithRefreshTokenTTL(48 * time.Hour)},
			payload: func() token.TokenPayload {
				p := refreshPayload()
				p.TTL = 0
				return p
			},
			wantTTL: 48 * time.Hour,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mustMaker(t, tt.opts...)
			got, err := m.ParseToken(mustSign(t, m, tt.payload()))
			if err != nil {
				t.Fatalf("ParseToken() unexpected error: %v", err)
			}
			if got.TTL > tt.wantTTL || got.TTL < tt.wantTTL-drift {
				t.Errorf("TTL = %s, want ~%s", got.TTL, tt.wantTTL)
			}
		})
	}
}

// ── ParseToken — round-trip ───────────────────────────────────────────────────

func TestParseToken_RoundTrip(t *testing.T) {
	m := mustMaker(t)

	tests := []struct {
		name    string
		payload token.TokenPayload
	}{
		{
			name:    "access token round-trip preserves all fields",
			payload: accessPayload(),
		},
		{
			name:    "refresh token round-trip preserves all fields",
			payload: refreshPayload(),
		},
		{
			name: "token version 42 is preserved",
			payload: func() token.TokenPayload {
				p := accessPayload()
				p.TokenVersion = 42
				return p
			}(),
		},
		{
			name: "token version 0 is preserved",
			payload: func() token.TokenPayload {
				p := accessPayload()
				p.TokenVersion = 0
				return p
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.ParseToken(mustSign(t, m, tt.payload))
			if err != nil {
				t.Fatalf("ParseToken() unexpected error: %v", err)
			}
			assertPayloadEqual(t, tt.payload, got)
		})
	}
}

// ── ParseToken — errors ───────────────────────────────────────────────────────

func TestParseToken_Errors(t *testing.T) {
	m := mustMaker(t)

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{
			name:    "empty string returns ErrInvalidToken",
			token:   "",
			wantErr: token.ErrInvalidToken,
		},
		{
			name:    "random garbage returns ErrInvalidToken",
			token:   "not-a-jwt-at-all",
			wantErr: token.ErrInvalidToken,
		},
		{
			name:    "two-part token returns ErrInvalidToken",
			token:   "header.payload",
			wantErr: token.ErrInvalidToken,
		},
		{
			name: "tampered signature returns ErrInvalidToken",
			token: func() string {
				s := mustSign(t, m, accessPayload())
				return s[:len(s)-4] + "XXXX"
			}(),
			wantErr: token.ErrInvalidToken,
		},
		{
			name: "tampered payload returns ErrInvalidToken",
			token: func() string {
				s := mustSign(t, m, accessPayload())
				parts := strings.Split(s, ".")
				parts[1] = strings.Repeat("A", len(parts[1]))
				return strings.Join(parts, ".")
			}(),
			wantErr: token.ErrInvalidToken,
		},
		{
			name: "token signed with different secret returns ErrInvalidToken",
			token: func() string {
				other, _ := token.NewJWTMaker("another-completely-different-secret-key!")
				return mustSign(t, other, accessPayload())
			}(),
			wantErr: token.ErrInvalidToken,
		},
		{
			// Classic JWT attack: alg=none bypasses signature verification.
			name:    "alg:none attack is rejected with ErrInvalidToken",
			token:   "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1aWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAifQ.",
			wantErr: token.ErrInvalidToken,
		},
		{
			name: "future nbf returns ErrInvalidToken",
			token: func() string {
				s, _ := m.CreateToken(time.Now().Add(10*time.Minute), accessPayload())
				return s
			}(),
			wantErr: token.ErrInvalidToken,
		},
		{
			name: "expired token returns ErrExpiredToken",
			token: func() string {
				p := accessPayload()
				p.TTL = time.Second
				s, _ := m.CreateToken(time.Now().Add(-time.Hour), p)
				return s
			}(),
			wantErr: token.ErrExpiredToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.ParseToken(tt.token)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseToken() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// ── Context helpers ───────────────────────────────────────────────────────────

func TestContext_NewAndFrom(t *testing.T) {
	payload := accessPayload()

	tests := []struct {
		name    string
		ctx     context.Context
		wantOk  bool
		wantNil bool
	}{
		{
			name:    "payload stored in context is retrievable",
			ctx:     token.NewContext(context.Background(), &payload),
			wantOk:  true,
			wantNil: false,
		},
		{
			name:    "nil payload stored in context returns ok=false",
			ctx:     token.NewContext(context.Background(), nil),
			wantOk:  false,
			wantNil: true,
		},
		{
			name:    "empty context returns ok=false",
			ctx:     context.Background(),
			wantOk:  false,
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := token.FromContext(tt.ctx)
			if ok != tt.wantOk {
				t.Errorf("FromContext() ok = %v, want %v", ok, tt.wantOk)
			}
			if (got == nil) != tt.wantNil {
				t.Errorf("FromContext() nil = %v, want %v", got == nil, tt.wantNil)
			}
		})
	}
}

func TestContext_PayloadIntegrity(t *testing.T) {
	want := accessPayload()
	ctx := token.NewContext(context.Background(), &want)

	tests := []struct {
		name  string
		check func(t *testing.T, got *token.TokenPayload)
	}{
		{
			name: "UserID is preserved through context",
			check: func(t *testing.T, got *token.TokenPayload) {
				if got.UserID != want.UserID {
					t.Errorf("UserID = %v, want %v", got.UserID, want.UserID)
				}
			},
		},
		{
			name: "SessionID is preserved through context",
			check: func(t *testing.T, got *token.TokenPayload) {
				if got.SessionID != want.SessionID {
					t.Errorf("SessionID = %v, want %v", got.SessionID, want.SessionID)
				}
			},
		},
		{
			name: "TokenType is preserved through context",
			check: func(t *testing.T, got *token.TokenPayload) {
				if got.Type != want.Type {
					t.Errorf("Type = %v, want %v", got.Type, want.Type)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := token.FromContext(ctx)
			if !ok {
				t.Fatal("FromContext() ok = false, want true")
			}
			tt.check(t, got)
		})
	}
}

// ── Interface compliance ──────────────────────────────────────────────────────

func TestJWTMaker_InterfaceCompliance(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "JWTMaker satisfies TokenMaker",
			run:  func(t *testing.T) { var _ token.TokenMaker = mustMaker(t) },
		},
		{
			name: "JWTMaker satisfies TokenParser",
			run:  func(t *testing.T) { var _ token.TokenParser = mustMaker(t) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}

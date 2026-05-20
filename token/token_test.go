package token_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/anhnmt/go-authxx/token"
)

// ── TokenType ─────────────────────────────────────────────────────────────────

func TestTokenType_Values(t *testing.T) {
	tests := []struct {
		name      string
		tokenType token.TokenType
		want      string
	}{
		{
			name:      "AccessToken value is access",
			tokenType: token.AccessToken,
			want:      "access",
		},
		{
			name:      "RefreshToken value is refresh",
			tokenType: token.RefreshToken,
			want:      "refresh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.tokenType); got != tt.want {
				t.Errorf("string(%v) = %q, want %q", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_AreDistinct(t *testing.T) {
	tests := []struct {
		name string
		a, b token.TokenType
	}{
		{
			name: "AccessToken and RefreshToken are distinct",
			a:    token.AccessToken,
			b:    token.RefreshToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.a == tt.b {
				t.Errorf("expected %v != %v", tt.a, tt.b)
			}
		})
	}
}

// ── Sentinel errors ───────────────────────────────────────────────────────────

func TestSentinelErrors_NotNil(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "ErrInvalidToken is not nil", err: token.ErrInvalidToken},
		{name: "ErrExpiredToken is not nil", err: token.ErrExpiredToken},
		{name: "ErrRevokedToken is not nil", err: token.ErrRevokedToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%v must not be nil", tt.err)
			}
		})
	}
}

func TestSentinelErrors_Messages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrInvalidToken message",
			err:  token.ErrInvalidToken,
			want: "token: invalid token",
		},
		{
			name: "ErrExpiredToken message",
			err:  token.ErrExpiredToken,
			want: "token: token has expired",
		},
		{
			name: "ErrRevokedToken message",
			err:  token.ErrRevokedToken,
			want: "token: token has been revoked",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSentinelErrors_AreDistinct(t *testing.T) {
	tests := []struct {
		name string
		a, b error
	}{
		{
			name: "ErrInvalidToken is distinct from ErrExpiredToken",
			a:    token.ErrInvalidToken,
			b:    token.ErrExpiredToken,
		},
		{
			name: "ErrInvalidToken is distinct from ErrRevokedToken",
			a:    token.ErrInvalidToken,
			b:    token.ErrRevokedToken,
		},
		{
			name: "ErrExpiredToken is distinct from ErrRevokedToken",
			a:    token.ErrExpiredToken,
			b:    token.ErrRevokedToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errors.Is(tt.a, tt.b) {
				t.Errorf("errors.Is(%v, %v) = true, want false", tt.a, tt.b)
			}
			if errors.Is(tt.b, tt.a) {
				t.Errorf("errors.Is(%v, %v) = true, want false", tt.b, tt.a)
			}
		})
	}
}

func TestSentinelErrors_MatchThemselves(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "ErrInvalidToken matches itself", err: token.ErrInvalidToken},
		{name: "ErrExpiredToken matches itself", err: token.ErrExpiredToken},
		{name: "ErrRevokedToken matches itself", err: token.ErrRevokedToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.err) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.err)
			}
		})
	}
}

func TestSentinelErrors_CanBeWrappedAndUnwrapped(t *testing.T) {
	tests := []struct {
		name    string
		wrapped error
		target  error
	}{
		{
			name:    "wrapped ErrExpiredToken is unwrappable",
			wrapped: errors.Join(token.ErrExpiredToken, errors.New("extra context")),
			target:  token.ErrExpiredToken,
		},
		{
			name:    "wrapped ErrInvalidToken is unwrappable",
			wrapped: errors.Join(token.ErrInvalidToken, errors.New("extra context")),
			target:  token.ErrInvalidToken,
		},
		{
			name:    "wrapped ErrRevokedToken is unwrappable",
			wrapped: errors.Join(token.ErrRevokedToken, errors.New("extra context")),
			target:  token.ErrRevokedToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.wrapped, tt.target) {
				t.Errorf("errors.Is(wrapped, %v) = false, want true", tt.target)
			}
		})
	}
}

// ── TokenPayload ──────────────────────────────────────────────────────────────

func TestTokenPayload_ZeroValue(t *testing.T) {
	var p token.TokenPayload

	tests := []struct {
		name string
		got  any
		want any
	}{
		{name: "UserID is uuid.Nil", got: p.UserID, want: uuid.UUID{}},
		{name: "SessionID is uuid.Nil", got: p.SessionID, want: uuid.UUID{}},
		{name: "TokenID is uuid.Nil", got: p.TokenID, want: uuid.UUID{}},
		{name: "Type is empty string", got: p.Type, want: token.TokenType("")},
		{name: "TokenVersion is 0", got: p.TokenVersion, want: int32(0)},
		{name: "TTL is 0", got: p.TTL, want: time.Duration(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}

func TestTokenPayload_FieldsAreAssignable(t *testing.T) {
	uid := uuid.New()
	sid := uuid.New()
	tid := uuid.New()

	tests := []struct {
		name    string
		payload token.TokenPayload
		check   func(t *testing.T, p token.TokenPayload)
	}{
		{
			name:    "UserID is stored correctly",
			payload: token.TokenPayload{UserID: uid},
			check: func(t *testing.T, p token.TokenPayload) {
				if p.UserID != uid {
					t.Errorf("UserID = %v, want %v", p.UserID, uid)
				}
			},
		},
		{
			name:    "SessionID is stored correctly",
			payload: token.TokenPayload{SessionID: sid},
			check: func(t *testing.T, p token.TokenPayload) {
				if p.SessionID != sid {
					t.Errorf("SessionID = %v, want %v", p.SessionID, sid)
				}
			},
		},
		{
			name:    "TokenID is stored correctly",
			payload: token.TokenPayload{TokenID: tid},
			check: func(t *testing.T, p token.TokenPayload) {
				if p.TokenID != tid {
					t.Errorf("TokenID = %v, want %v", p.TokenID, tid)
				}
			},
		},
		{
			name:    "TokenVersion is stored correctly",
			payload: token.TokenPayload{TokenVersion: 7},
			check: func(t *testing.T, p token.TokenPayload) {
				if p.TokenVersion != 7 {
					t.Errorf("TokenVersion = %d, want 7", p.TokenVersion)
				}
			},
		},
		{
			name:    "TTL is stored correctly",
			payload: token.TokenPayload{TTL: 30 * time.Minute},
			check: func(t *testing.T, p token.TokenPayload) {
				if p.TTL != 30*time.Minute {
					t.Errorf("TTL = %s, want 30m", p.TTL)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, tt.payload)
		})
	}
}

// ── Interface compliance ──────────────────────────────────────────────────────

func TestJWTMaker_SatisfiesInterfaces(t *testing.T) {
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

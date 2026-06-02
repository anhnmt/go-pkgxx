package token_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/anhnmt/go-pkgxx/token"
)

// ── TokenType ─────────────────────────────────────────────────────────────────

func TestTokenType_Values(t *testing.T) {
	tests := []struct {
		name      string
		tokenType token.TokenType
		want      string
	}{
		{
			name:      "AccessToken string value is access",
			tokenType: token.AccessToken,
			want:      "access",
		},
		{
			name:      "RefreshToken string value is refresh",
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
				t.Errorf("%v == %v, want distinct values", tt.a, tt.b)
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
				t.Errorf("expected non-nil error, got nil")
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
			name: "ErrInvalidToken has correct message",
			err:  token.ErrInvalidToken,
			want: "token: invalid token",
		},
		{
			name: "ErrExpiredToken has correct message",
			err:  token.ErrExpiredToken,
			want: "token: token has expired",
		},
		{
			name: "ErrRevokedToken has correct message",
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

func TestSentinelErrors_CanBeWrapped(t *testing.T) {
	tests := []struct {
		name   string
		target error
	}{
		{name: "ErrInvalidToken survives wrapping", target: token.ErrInvalidToken},
		{name: "ErrExpiredToken survives wrapping", target: token.ErrExpiredToken},
		{name: "ErrRevokedToken survives wrapping", target: token.ErrRevokedToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := errors.Join(tt.target, errors.New("extra context"))
			if !errors.Is(wrapped, tt.target) {
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

func TestTokenPayload_Fields(t *testing.T) {
	uid, sid, tid := uuid.New(), uuid.New(), uuid.New()

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
		{
			name:    "AccessToken type is stored correctly",
			payload: token.TokenPayload{Type: token.AccessToken},
			check: func(t *testing.T, p token.TokenPayload) {
				if p.Type != token.AccessToken {
					t.Errorf("Type = %v, want %v", p.Type, token.AccessToken)
				}
			},
		},
		{
			name:    "RefreshToken type is stored correctly",
			payload: token.TokenPayload{Type: token.RefreshToken},
			check: func(t *testing.T, p token.TokenPayload) {
				if p.Type != token.RefreshToken {
					t.Errorf("Type = %v, want %v", p.Type, token.RefreshToken)
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

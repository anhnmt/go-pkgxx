package token

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ── Sentinel errors ───────────────────────────────────────────────────────────

var (
	// ErrInvalidToken is returned when a token cannot be parsed or its signature is invalid.
	ErrInvalidToken = errors.New("token: invalid token")

	// ErrExpiredToken is returned when a token is structurally valid but has passed its expiry time.
	ErrExpiredToken = errors.New("token: token has expired")

	// ErrRevokedToken is returned when a session has been explicitly revoked
	// (force logout by device or force logout all).
	ErrRevokedToken = errors.New("token: token has been revoked")
)

// ── Interfaces ────────────────────────────────────────────────────────────────

// TokenMaker creates signed tokens.
type TokenMaker interface {
	CreateToken(now time.Time, payload TokenPayload) (string, error)
}

// TokenParser validates and parses tokens back into a payload.
// Kept separate so read-only services only need the parser, not the signing key.
type TokenParser interface {
	ParseToken(tokenStr string) (*TokenPayload, error)
}

// ── Payload ───────────────────────────────────────────────────────────────────

// TokenPayload carries the data embedded inside a token.
// DeviceID is intentionally omitted — it lives in the session store,
// reachable via SessionID.
type TokenPayload struct {
	UserID       uuid.UUID
	SessionID    uuid.UUID // one session per device
	TokenID      uuid.UUID // jti — used for per-token blacklisting
	Type         TokenType
	TokenVersion int32         // bump to invalidate all tokens for a user (force logout all)
	TTL          time.Duration // 0 → use maker default for the token type
}

// ── TokenType ─────────────────────────────────────────────────────────────────

// TokenType distinguishes access tokens from refresh tokens.
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

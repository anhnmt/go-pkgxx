package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ── Context helpers ───────────────────────────────────────────────────────────

type contextKey struct{}

// NewContext stores a TokenPayload in the context.
func NewContext(ctx context.Context, payload *TokenPayload) context.Context {
	return context.WithValue(ctx, contextKey{}, payload)
}

// FromContext retrieves a TokenPayload from the context.
func FromContext(ctx context.Context) (*TokenPayload, bool) {
	payload, ok := ctx.Value(contextKey{}).(*TokenPayload)
	return payload, ok
}

// ── Defaults ──────────────────────────────────────────────────────────────────

const (
	defaultAccessTokenTTL  = 15 * time.Minute
	defaultRefreshTokenTTL = 7 * 24 * time.Hour
)

// ── Options ───────────────────────────────────────────────────────────────────

// Option configures a JWTMaker.
type Option func(*JWTMaker) error

// WithAccessTokenTTL overrides the default access token TTL (default: 15m).
func WithAccessTokenTTL(d time.Duration) Option {
	return func(m *JWTMaker) error {
		if d <= 0 {
			return fmt.Errorf("token: access token TTL must be positive, got %s", d)
		}
		m.accessTokenTTL = d
		return nil
	}
}

// WithRefreshTokenTTL overrides the default refresh token TTL (default: 7d).
func WithRefreshTokenTTL(d time.Duration) Option {
	return func(m *JWTMaker) error {
		if d <= 0 {
			return fmt.Errorf("token: refresh token TTL must be positive, got %s", d)
		}
		m.refreshTokenTTL = d
		return nil
	}
}

// ── JWTMaker ──────────────────────────────────────────────────────────────────

// JWTMaker implements TokenMaker and TokenParser using HMAC-signed JWTs.
type JWTMaker struct {
	secretKey       []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

// NewJWTMaker creates a JWTMaker. The secret must be at least 32 bytes.
// TTLs default to 15 minutes (access) and 7 days (refresh).
//
// Example:
//
//	m, err := token.NewJWTMaker(secret,
//	    token.WithAccessTokenTTL(30 * time.Minute),
//	    token.WithRefreshTokenTTL(30 * 24 * time.Hour),
//	)
func NewJWTMaker(secretKey string, opts ...Option) (*JWTMaker, error) {
	if len(secretKey) < 32 {
		return nil, fmt.Errorf("token: secret key must be at least 32 bytes, got %d", len(secretKey))
	}

	m := &JWTMaker{
		secretKey:       []byte(secretKey),
		accessTokenTTL:  defaultAccessTokenTTL,
		refreshTokenTTL: defaultRefreshTokenTTL,
	}

	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, err
		}
	}

	return m, nil
}

// AccessTokenTTL returns the configured access token TTL.
func (m *JWTMaker) AccessTokenTTL() time.Duration { return m.accessTokenTTL }

// RefreshTokenTTL returns the configured refresh token TTL.
func (m *JWTMaker) RefreshTokenTTL() time.Duration { return m.refreshTokenTTL }

// ── Claims ────────────────────────────────────────────────────────────────────

// jwtClaims holds standard JWT fields plus our custom payload.
// UUID fields must NOT use omitempty — a zero UUID is still a valid value
// and omitting it would silently lose data on round-trip.
type jwtClaims struct {
	jwt.RegisteredClaims

	UserID       uuid.UUID `json:"uid"`
	SessionID    uuid.UUID `json:"sid"`
	Type         TokenType `json:"typ"`
	TokenVersion int32     `json:"ver"`
}

// ── CreateToken ───────────────────────────────────────────────────────────────

// CreateToken signs a new JWT for the given payload.
// TTL resolution order: payload.TTL (if > 0) → maker default for that token type.
func (m *JWTMaker) CreateToken(now time.Time, payload TokenPayload) (string, error) {
	ttl := payload.TTL
	if ttl <= 0 {
		switch payload.Type {
		case RefreshToken:
			ttl = m.refreshTokenTTL
		default:
			ttl = m.accessTokenTTL
		}
	}

	claims := jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        payload.TokenID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		UserID:       payload.UserID,
		SessionID:    payload.SessionID,
		Type:         payload.Type,
		TokenVersion: payload.TokenVersion,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signed, err := t.SignedString(m.secretKey)
	if err != nil {
		return "", fmt.Errorf("token: failed to sign JWT: %w", err)
	}

	return signed, nil
}

// ── ParseToken ────────────────────────────────────────────────────────────────

// ParseToken validates the token string and returns the original payload.
func (m *JWTMaker) ParseToken(tokenStr string) (*TokenPayload, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("token: unexpected signing method: %v", t.Header["alg"])
		}
		return m.secretKey, nil
	})
	if err != nil {
		return nil, mapJWTError(err)
	}

	claims, ok := t.Claims.(*jwtClaims)
	if !ok || !t.Valid {
		return nil, ErrInvalidToken
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return &TokenPayload{
		UserID:       claims.UserID,
		SessionID:    claims.SessionID,
		TokenID:      tokenID,
		Type:         claims.Type,
		TokenVersion: claims.TokenVersion,
		TTL:          time.Until(claims.ExpiresAt.Time),
	}, nil
}

// ── error mapping ─────────────────────────────────────────────────────────────

func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return ErrExpiredToken
	case errors.Is(err, jwt.ErrTokenNotValidYet),
		errors.Is(err, jwt.ErrTokenMalformed),
		errors.Is(err, jwt.ErrTokenSignatureInvalid),
		errors.Is(err, jwt.ErrTokenUnverifiable):
		return ErrInvalidToken
	default:
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
}

// Package domain is the model of the AXLR tool registry: the write side of
// the catalog the console installs from. See
// docs/plans/2026-10-17-tool-registry-domain.md.
package domain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
)

var publisherIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)

// PublisherID names a publisher.
type PublisherID string

// NewPublisherID validates a publisher id.
func NewPublisherID(raw string) (PublisherID, error) {
	if !publisherIDPattern.MatchString(raw) {
		return "", errors.New("invalid publisher id: [a-z0-9][a-z0-9-]{1,31}")
	}
	return PublisherID(raw), nil
}

// KeyID identifies a publisher key: the first 16 hex characters of the
// SHA-256 of the public key.
type KeyID string

// KeyIDOf derives the id of a public key.
func KeyIDOf(key ed25519.PublicKey) KeyID {
	sum := sha256.Sum256(key)
	return KeyID(hex.EncodeToString(sum[:8]))
}

// PublisherKey is one Ed25519 public key of a publisher.
type PublisherKey struct {
	ID        KeyID
	Key       ed25519.PublicKey
	AddedAt   time.Time
	RevokedAt time.Time // zero while active
}

// Active says whether the key verifies signatures at t.
func (k PublisherKey) Active(t time.Time) bool {
	return k.RevokedAt.IsZero() || t.Before(k.RevokedAt)
}

// TokenDigest is the SHA-256 of an API token; the token itself is never
// stored.
type TokenDigest string

// DigestToken hashes a token for storage and lookup.
func DigestToken(token string) TokenDigest {
	sum := sha256.Sum256([]byte(token))
	return TokenDigest(hex.EncodeToString(sum[:]))
}

// Scope is a tool name a token may publish: an exact name or a prefix
// ending in "_*".
type Scope string

// Covers says whether the scope allows name.
func (s Scope) Covers(name ToolName) bool {
	if prefix, ok := strings.CutSuffix(string(s), "*"); ok {
		return strings.HasPrefix(string(name), prefix)
	}
	return string(s) == string(name)
}

// Token is a stored API token: its digest, scopes and expiry.
type Token struct {
	Digest    TokenDigest
	Scopes    []Scope
	ExpiresAt time.Time // zero means no expiry
	RevokedAt time.Time
}

// Publisher owns tool names and signs bundles.
type Publisher struct {
	ID         PublisherID
	Namespaces []Scope // the names the publisher may own at all
	Keys       []PublisherKey
	Tokens     []Token
}

// NewPublisher registers a publisher with its first key and namespaces.
func NewPublisher(id PublisherID, key ed25519.PublicKey, namespaces []Scope, now time.Time) (*Publisher, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("a publisher key is a 32-byte Ed25519 public key")
	}
	if len(namespaces) == 0 {
		return nil, errors.New("a publisher needs at least one namespace")
	}
	return &Publisher{ID: id, Namespaces: namespaces, Keys: []PublisherKey{{ID: KeyIDOf(key), Key: key, AddedAt: now}}}, nil
}

// Owns says whether name is inside the publisher's namespaces.
func (p *Publisher) Owns(name ToolName) bool {
	for _, ns := range p.Namespaces {
		if ns.Covers(name) {
			return true
		}
	}
	return false
}

// AddKey registers another signing key.
func (p *Publisher) AddKey(key ed25519.PublicKey, now time.Time) (KeyID, error) {
	if len(key) != ed25519.PublicKeySize {
		return "", errors.New("a publisher key is a 32-byte Ed25519 public key")
	}
	id := KeyIDOf(key)
	for _, k := range p.Keys {
		if k.ID == id {
			return "", errors.New("key already registered")
		}
	}
	p.Keys = append(p.Keys, PublisherKey{ID: id, Key: key, AddedAt: now})
	return id, nil
}

// RevokeKey stops a key from verifying anything signed from now on.
func (p *Publisher) RevokeKey(id KeyID, now time.Time) error {
	for i := range p.Keys {
		if p.Keys[i].ID == id {
			if !p.Keys[i].RevokedAt.IsZero() {
				return errors.New("key already revoked")
			}
			p.Keys[i].RevokedAt = now
			return nil
		}
	}
	return errors.New("unknown key")
}

// ActiveKey returns the key with id when it is active at t.
func (p *Publisher) ActiveKey(id KeyID, t time.Time) (PublisherKey, bool) {
	for _, k := range p.Keys {
		if k.ID == id && k.Active(t) {
			return k, true
		}
	}
	return PublisherKey{}, false
}

// IssueToken records a token's digest with its scopes; the caller shows
// the token once and forgets it.
func (p *Publisher) IssueToken(token string, scopes []Scope, expiresAt time.Time) error {
	if len(token) < 32 {
		return errors.New("a token has at least 32 characters")
	}
	if len(scopes) == 0 {
		return errors.New("a token needs at least one scope")
	}
	for _, s := range scopes {
		if !p.ownsScope(s) {
			return errors.New("scope " + string(s) + " is outside the publisher's namespaces")
		}
	}
	p.Tokens = append(p.Tokens, Token{Digest: DigestToken(token), Scopes: scopes, ExpiresAt: expiresAt})
	return nil
}

func (p *Publisher) ownsScope(s Scope) bool {
	for _, ns := range p.Namespaces {
		if ns.Covers(ToolName(strings.TrimSuffix(string(s), "*"))) || ns == s {
			return true
		}
	}
	return false
}

// RevokeToken revokes the token with the given digest.
func (p *Publisher) RevokeToken(digest TokenDigest, now time.Time) error {
	for i := range p.Tokens {
		if p.Tokens[i].Digest == digest && p.Tokens[i].RevokedAt.IsZero() {
			p.Tokens[i].RevokedAt = now
			return nil
		}
	}
	return errors.New("unknown or revoked token")
}

// Authorize says whether the token (by digest) may publish name at t.
func (p *Publisher) Authorize(digest TokenDigest, name ToolName, t time.Time) error {
	for _, tok := range p.Tokens {
		if tok.Digest != digest {
			continue
		}
		if !tok.RevokedAt.IsZero() {
			return errors.New("token revoked")
		}
		if !tok.ExpiresAt.IsZero() && !t.Before(tok.ExpiresAt) {
			return errors.New("token expired")
		}
		for _, s := range tok.Scopes {
			if s.Covers(name) && p.Owns(name) {
				return nil
			}
		}
		return errors.New("token scope does not cover " + string(name))
	}
	return errors.New("unknown token")
}

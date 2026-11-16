package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// userErr is an error message that is safe to show to the user.
type userErr string

func (e userErr) Error() string { return string(e) }

func bad(format string, a ...any) error { return userErr(fmt.Sprintf(format, a...)) }

var (
	labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	localRe = regexp.MustCompile(`^[a-z0-9_+-]+(\.[a-z0-9_+-]+)*$`)
)

func normDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 253 || !strings.Contains(s, ".") {
		return "", bad("invalid domain %q", s)
	}
	for _, l := range strings.Split(s, ".") {
		if !labelRe.MatchString(l) {
			return "", bad("invalid domain %q", s)
		}
	}
	return s, nil
}

// normAddr lowercases and validates an email address.
func normAddr(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	i := strings.LastIndex(s, "@")
	if i < 1 || len(s) > 254 || i > 64 || strings.Count(s, "@") != 1 {
		return "", bad("invalid address %q", s)
	}
	if !localRe.MatchString(s[:i]) {
		return "", bad("invalid address %q", s)
	}
	if _, err := normDomain(s[i+1:]); err != nil {
		return "", bad("invalid address %q", s)
	}
	return s, nil
}

func domainOf(addr string) string { return addr[strings.LastIndex(addr, "@")+1:] }

// splitList splits on commas, semicolons and whitespace.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

// normForward validates a forward list and returns it comma-joined, no spaces.
func normForward(s, self string) (string, error) {
	var out []string
	seen := map[string]bool{}
	for _, p := range splitList(s) {
		a, err := normAddr(p)
		if err != nil {
			return "", err
		}
		if a == self {
			return "", bad("cannot forward to itself")
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return strings.Join(out, ","), nil
}

func checkPassword(p string) error {
	if len([]rune(p)) < 10 {
		return bad("password must be at least 10 characters")
	}
	if len(p) > 72 {
		return bad("password must be at most 72 bytes")
	}
	return nil
}

const pwAlphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func genPassword() string {
	b := make([]byte, 16)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(pwAlphabet))))
		if err != nil {
			panic(err)
		}
		b[i] = pwAlphabet[n.Int64()]
	}
	return string(b)
}

const pwPrefix = "{BLF-CRYPT}"

func hashPassword(p string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(p), 10)
	if err != nil {
		return "", err
	}
	return pwPrefix + string(h), nil
}

func verifyPassword(stored, p string) bool {
	if !strings.HasPrefix(stored, pwPrefix) {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(strings.TrimPrefix(stored, pwPrefix)), []byte(p)) == nil
}

var errNotFound = errors.New("not found")

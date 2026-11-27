// Package avatar builds Gravatar image URLs. See DETAILS.md §Gravatar.
package avatar

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
)

// Gravatar returns the image URL for email (SHA-256 of the trimmed, lower-cased address).
func Gravatar(email string, size int, fallback string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	q := url.Values{}
	q.Set("s", strconv.Itoa(size))
	if fallback == "" {
		fallback = "identicon"
	}
	q.Set("d", fallback)
	q.Set("r", "g")
	return "https://gravatar.com/avatar/" + hex.EncodeToString(sum[:]) + "?" + q.Encode()
}

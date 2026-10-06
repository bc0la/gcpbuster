// Package testfixture generates fake credential-shaped values for offline tests.
// These values are never issued by a provider and must never be validated.
package testfixture

import "hash/crc32"

// GitHubToken uses an explicitly synthetic body and the documented format
// checksum so Kingfisher can exercise its offline rule requirements. Keeping
// generated fixtures out of source literals also avoids publishing token-shaped
// strings that repository push protection would mistake for issued credentials.
func GitHubToken() string {
	const body = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0"
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	sum := crc32.ChecksumIEEE([]byte(body))
	checksum := [6]byte{'0', '0', '0', '0', '0', '0'}
	for i := len(checksum) - 1; i >= 0 && sum > 0; i-- {
		checksum[i] = alphabet[sum%62]
		sum /= 62
	}
	return "ghp_" + body + string(checksum[:])
}

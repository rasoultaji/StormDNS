// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import "strings"

// IsAllowedAuthFQDN returns true iff fqdn equals one of authDomains
// or is a subdomain of one. Comparison is case-insensitive and ignores
// trailing dots.
func IsAllowedAuthFQDN(fqdn string, authDomains []string) bool {
	f := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	for _, a := range authDomains {
		n := strings.ToLower(strings.TrimSuffix(a, "."))
		if f == n || strings.HasSuffix(f, "."+n) {
			return true
		}
	}
	return false
}

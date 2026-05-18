// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package antidpi

// DefaultDictionary is a small embedded vocabulary of innocuous DNS-label
// fragments. Each entry is 2..12 chars, [a-z0-9-]. Operators can override.
var DefaultDictionary = []string{
	"api", "app", "cdn", "img", "ws", "ws1", "s3", "v1", "v2",
	"edge", "edge1", "edge2", "static", "media", "assets", "data",
	"auth", "login", "proxy", "ws-api", "lb", "ingress", "egress",
	"eu", "us", "asia", "eu-west", "us-east", "ap-south",
	"stage", "prod", "qa", "test", "ops", "metrics", "logs",
	"web", "www", "mail", "smtp", "ftp", "vpn", "git",
}

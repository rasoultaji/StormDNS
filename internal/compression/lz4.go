// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package compression

// CompressLZ4 compresses data using LZ4 codec.
func CompressLZ4(src []byte) ([]byte, error) {
	return compressLZ4(src)
}

// DecompressLZ4 decompresses LZ4-compressed data.
func DecompressLZ4(src []byte) ([]byte, error) {
	return decompressLZ4(src)
}

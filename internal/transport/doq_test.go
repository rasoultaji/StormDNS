// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func mkDoQEcho(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		ctx := context.Background()
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				for {
					str, err := c.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func(s *quic.Stream) {
						defer s.Close()
						hdr := make([]byte, 2)
						if _, err := io.ReadFull(s, hdr); err != nil {
							return
						}
						n := binary.BigEndian.Uint16(hdr)
						body := make([]byte, n)
						if _, err := io.ReadFull(s, body); err != nil {
							return
						}
						resp := make([]byte, 2+int(n))
						binary.BigEndian.PutUint16(resp[:2], n)
						copy(resp[2:], body)
						_, _ = s.Write(resp)
					}(str)
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestDoQ_BidiStreamRoundTrip(t *testing.T) {
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	addr := mkDoQEcho(t, cert)

	ch, err := NewDoQChannel(addr, 3*time.Second, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
	})
	if err != nil {
		t.Fatalf("NewDoQChannel: %v", err)
	}
	defer ch.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := []byte{0xAB, 0xCD, 0xEF}
	r, err := ch.Query(ctx, q)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !bytes.Equal(r, q) {
		t.Fatalf("echo mismatch: got %x, want %x", r, q)
	}
	if ch.Kind() != KindDoQ {
		t.Fatalf("kind mismatch: got %v, want %v", ch.Kind(), KindDoQ)
	}
}

// compile-time guard for imported but otherwise unused symbols
var _ = binary.BigEndian
var _ = io.EOF

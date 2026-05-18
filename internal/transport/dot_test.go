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
	"net"
	"testing"
	"time"
)

func mkDoTEcho(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				hdr := make([]byte, 2)
				for {
					if _, err := io.ReadFull(conn, hdr); err != nil {
						return
					}
					n := binary.BigEndian.Uint16(hdr)
					buf := make([]byte, n)
					if _, err := io.ReadFull(conn, buf); err != nil {
						return
					}
					out := make([]byte, 2+len(buf))
					binary.BigEndian.PutUint16(out, uint16(len(buf)))
					copy(out[2:], buf)
					_, _ = conn.Write(out)
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestDoT_FramedRoundTrip(t *testing.T) {
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	addr := mkDoTEcho(t, cert)
	ch, err := NewDoTChannel(addr, 2*time.Second, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("NewDoTChannel: %v", err)
	}
	defer ch.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	r, err := ch.Query(ctx, q)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !bytes.Equal(r, q) {
		t.Fatalf("echo mismatch: %x", r)
	}
	if ch.Kind() != KindDoT {
		t.Fatal("kind mismatch")
	}
}

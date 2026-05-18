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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDoH_PostsRFC8484(t *testing.T) {
	var gotCT, gotBody []byte
	var contentType string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotCT = []byte(contentType)
		gotBody = b
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte{0xAA, 0xBB, 0xCC})
	}))
	defer srv.Close()

	ch, err := NewDoHChannel(srv.URL+"/dns-query", 2*time.Second, withInsecureTLS())
	if err != nil {
		t.Fatalf("NewDoHChannel: %v", err)
	}
	defer ch.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, err := ch.Query(ctx, []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !bytes.Equal(r, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("response mismatch: %x", r)
	}
	if string(gotCT) != "application/dns-message" {
		t.Fatalf("Content-Type was %q", gotCT)
	}
	if !bytes.Equal(gotBody, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("body mismatch")
	}
	if ch.Kind() != KindDoH {
		t.Fatal("kind mismatch")
	}
}

func withInsecureTLS() DoHOption {
	return func(o *dohOptions) {
		o.tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}
}

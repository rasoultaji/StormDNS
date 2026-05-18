// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package handshake

import (
	"bytes"
	"testing"
	"time"
)

func TestRekey_ClientInitiatesServerResponds(t *testing.T) {
	psk := bytes.Repeat([]byte{0x42}, 32)
	// Reuse the handshake flow: ClientStart/ServerAccept work without AAD.
	cs, env, err := ClientStart(psk, 0, time.Now().UTC())
	if err != nil {
		t.Fatalf("ClientStart: %v", err)
	}
	ss, ack, err := ServerAccept(psk, env, cs.ClientRandom)
	if err != nil {
		t.Fatalf("ServerAccept: %v", err)
	}
	if err := cs.Finish(psk, ack, ss.ServerRandom); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	rk := NewRekeyCoordinator(IsClient, psk)
	ephPub, _, err := rk.Start(cs.Keys)
	if err != nil {
		t.Fatalf("rekey start: %v", err)
	}
	if len(ephPub) != 32 {
		t.Fatalf("eph pub size = %d", len(ephPub))
	}

	srk := NewRekeyCoordinator(IsServer, psk)
	peerPub, _, err := srk.HandlePeer(ss.Keys, ephPub)
	if err != nil {
		t.Fatalf("server handle: %v", err)
	}
	newServerKeys := srk.NewKeys()

	finalClient, err := rk.Finish(peerPub)
	if err != nil {
		t.Fatalf("client finish: %v", err)
	}
	if !bytes.Equal(finalClient.ClientToServer, newServerKeys.ClientToServer) {
		t.Fatal("rekeyed K_c2s diverged across sides")
	}
	if !bytes.Equal(finalClient.ServerToClient, newServerKeys.ServerToClient) {
		t.Fatal("rekeyed K_s2c diverged across sides")
	}
	if bytes.Equal(finalClient.ClientToServer, cs.Keys.ClientToServer) {
		t.Fatal("rekey did not change K_c2s")
	}
}

func TestRekey_CollisionClientWins(t *testing.T) {
	psk := bytes.Repeat([]byte{0x42}, 32)
	rkClient := NewRekeyCoordinator(IsClient, psk)
	rkServer := NewRekeyCoordinator(IsServer, psk)

	keys := SessionKeys{
		ClientToServer: bytes.Repeat([]byte{1}, 32),
		ServerToClient: bytes.Repeat([]byte{2}, 32),
	}

	clientEph, _, _ := rkClient.Start(keys)
	_, _, _ = rkServer.Start(keys) // server also started

	_, _, err := rkServer.HandlePeer(keys, clientEph)
	if err != nil {
		t.Fatalf("server handle on collision: %v", err)
	}
	if rkServer.state != rekeyStateAdoptedClient {
		t.Fatalf("server state = %v, want adoptedClient", rkServer.state)
	}
}

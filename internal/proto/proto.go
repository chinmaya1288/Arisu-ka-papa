// Package proto holds the wire types and signing helpers shared by server and loader.
package proto

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

type LoginReq struct {
	DeviceID string `json:"device_id"`
	Key      string `json:"key"`
}

type LoginResp struct {
	Token         string `json:"token"`      // bearer token for /v1/payload
	TokenExpires  int64  `json:"token_exp"`  // unix
	LicenseExpiry int64  `json:"license_exp"` // unix
	AllowOffline  bool   `json:"allow_offline"`
	Lease         string `json:"lease"` // base64 ed25519 sig over LeaseMsg
	PayloadSHA256 string `json:"payload_sha256"`
	PayloadSig    string `json:"payload_sig"` // base64 ed25519 sig over raw sha256 hex string
}

func LeaseMsg(deviceID string, exp int64) []byte {
	return []byte(fmt.Sprintf("lease|%s|%d", deviceID, exp))
}

func Verify(pub ed25519.PublicKey, msg []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	return err == nil && ed25519.Verify(pub, msg, sig)
}

func Sign(priv ed25519.PrivateKey, msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
}

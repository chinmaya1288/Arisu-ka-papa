// Auth + distribution server.
//
//	server keygen                 create signing key (signing.key, prints public key)
//	server serve                  run the API
//
// Env: FPS_ADDR (:8080) FPS_KEYS (Arisukapapa.json) FPS_PAYLOAD (payload.bin)
//      FPS_SIGNKEY (signing.key) FPS_SECRET (token HMAC secret, required)
package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"fpsbooster/internal/proto"
)

const dateLayout = "02-01-2006"

type License struct {
	DeviceID     string `json:"device_id"`
	Key          string `json:"key"`
	ExpiryDate   string `json:"expirydate"`
	AllowOffline bool   `json:"Allowoffline"`
}

type server struct {
	mu       sync.Mutex
	keysPath string
	licenses []License
	priv     ed25519.PrivateKey
	secret   []byte
	payload  string

	rl map[string][]time.Time // ip -> recent login attempts
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: server keygen|serve")
	}
	signPath := env("FPS_SIGNKEY", "signing.key")
	switch os.Args[1] {
	case "keygen":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		if err := os.WriteFile(signPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0600); err != nil {
			log.Fatal(err)
		}
		fmt.Println("public key (put in loader build as PUBKEY):")
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
	case "serve":
		serve(signPath)
	default:
		log.Fatal("unknown command")
	}
}

func serve(signPath string) {
	secret := os.Getenv("FPS_SECRET")
	if len(secret) < 16 {
		log.Fatal("FPS_SECRET must be set (>=16 chars)")
	}
	raw, err := os.ReadFile(signPath)
	if err != nil {
		log.Fatalf("signing key: %v (run keygen)", err)
	}
	pb, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(pb) != ed25519.PrivateKeySize {
		log.Fatal("bad signing key")
	}
	s := &server{
		keysPath: env("FPS_KEYS", "Arisukapapa.json"),
		priv:     ed25519.PrivateKey(pb),
		secret:   []byte(secret),
		payload:  env("FPS_PAYLOAD", "payload.bin"),
		rl:       map[string][]time.Time{},
	}
	if err := s.loadKeys(); err != nil {
		log.Fatalf("keys: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/login", s.login)
	mux.HandleFunc("/v1/payload", s.download)
	addr := env("FPS_ADDR", ":8080")
	log.Printf("listening on %s (put behind TLS: caddy/nginx)", addr)
	log.Fatal((&http.Server{Addr: addr, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 120 * time.Second}).ListenAndServe())
}

func (s *server) loadKeys() error {
	b, err := os.ReadFile(s.keysPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &s.licenses)
}

func (s *server) saveKeys() error {
	b, _ := json.MarshalIndent(s.licenses, "", "    ")
	tmp := s.keysPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.keysPath)
}

func (s *server) limited(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var keep []time.Time
	for _, t := range s.rl[ip] {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	s.rl[ip] = keep
	return len(keep) > 10
}

func ip(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" { // behind our own reverse proxy
		return strings.TrimSpace(strings.Split(f, ",")[0])
	}
	h := r.RemoteAddr
	if i := strings.LastIndex(h, ":"); i > 0 {
		h = h[:i]
	}
	return h
}

func eq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (s *server) token(device string, exp int64) string {
	body := device + "|" + strconv.FormatInt(exp, 10)
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString([]byte(body)) + "." + hex.EncodeToString(m.Sum(nil))
}

func (s *server) checkToken(tok string) (string, bool) {
	i := strings.LastIndex(tok, ".")
	if i < 0 {
		return "", false
	}
	body, err := base64.RawURLEncoding.DecodeString(tok[:i])
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(body), "|")
	if len(parts) != 2 {
		return "", false
	}
	exp, _ := strconv.ParseInt(parts[1], 10, 64)
	if time.Now().Unix() > exp || !eq(s.token(parts[0], exp), tok) {
		return "", false
	}
	return parts[0], true
}

func (s *server) payloadInfo() (shaHex string, err error) {
	b, err := os.ReadFile(s.payload)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func fail(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "method")
		return
	}
	if s.limited(ip(r)) {
		fail(w, 429, "too many attempts")
		return
	}
	var req proto.LoginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.DeviceID == "" || req.Key == "" {
		fail(w, 400, "bad request")
		return
	}

	s.mu.Lock()
	var lic *License
	for i := range s.licenses {
		if eq(s.licenses[i].Key, req.Key) {
			lic = &s.licenses[i]
			break
		}
	}
	if lic == nil {
		s.mu.Unlock()
		fail(w, 401, "invalid key")
		return
	}
	if lic.DeviceID == "" { // first use binds the key to this device
		lic.DeviceID = req.DeviceID
		if err := s.saveKeys(); err != nil {
			log.Printf("save keys: %v", err)
		}
	}
	l := *lic
	s.mu.Unlock()

	if !eq(l.DeviceID, req.DeviceID) {
		fail(w, 403, "key bound to another device")
		return
	}
	// license valid through the end of the expiry day
	exp, err := time.Parse(dateLayout, l.ExpiryDate)
	if err != nil {
		fail(w, 500, "bad license data")
		return
	}
	licExp := exp.Add(24 * time.Hour).Unix()
	if time.Now().Unix() > licExp {
		fail(w, 403, "license expired")
		return
	}
	sha, err := s.payloadInfo()
	if err != nil {
		fail(w, 503, "payload unavailable")
		return
	}

	tokExp := time.Now().Add(15 * time.Minute).Unix()
	resp := proto.LoginResp{
		Token:         s.token(l.DeviceID, tokExp),
		TokenExpires:  tokExp,
		LicenseExpiry: licExp,
		AllowOffline:  l.AllowOffline,
		PayloadSHA256: sha,
		PayloadSig:    proto.Sign(s.priv, []byte(sha)),
	}
	if l.AllowOffline {
		resp.Lease = proto.Sign(s.priv, proto.LeaseMsg(l.DeviceID, licExp))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *server) download(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if _, ok := s.checkToken(tok); !ok {
		fail(w, 401, "unauthorized")
		return
	}
	f, err := os.Open(s.payload)
	if err != nil {
		fail(w, 503, "payload unavailable")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "payload", time.Time{}, f)
}

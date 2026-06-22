// Command jwks converts a PEM-encoded public or private key into a JWKS
// (JSON Web Key Set) suitable for registering a Buildkite Token Exchange
// application. RSA (RS256) and ECDSA P-256 (ES256) keys are supported.
//
// You can point it at either the public key or the private key — for a private
// key the public key is derived automatically.
//
// Usage:
//
//	go run ./examples/jwks -key public_key.pem -kid my-key-1
//	go run ./examples/jwks -key private_key.pem -kid my-key-1
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/buildkite/tokenexchange"
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`

	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func main() {
	keyFile := flag.String("key", "", "path to a PEM public or private key (required)")
	kid := flag.String("kid", "", "key ID (kid) to assign (required; must match your JWT header)")
	flag.Parse()

	if *keyFile == "" || *kid == "" {
		flag.Usage()
		os.Exit(1)
	}

	pub, err := loadPublicKey(*keyFile)
	if err != nil {
		log.Fatalf("loading key: %v", err)
	}

	key, err := toJWK(pub, *kid)
	if err != nil {
		log.Fatalf("building JWK: %v", err)
	}

	out, err := json.MarshalIndent(struct {
		Keys []jwk `json:"keys"`
	}{Keys: []jwk{key}}, "", "  ")
	if err != nil {
		log.Fatalf("encoding JWKS: %v", err)
	}
	fmt.Println(string(out))
}

// loadPublicKey reads a PEM file and returns its public key, accepting either a
// public key (PKIX "PUBLIC KEY") or a private key (from which the public key is
// derived).
func loadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}

	signer, err := tokenexchange.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("not a recognized public or private key: %w", err)
	}
	return signer.Public(), nil
}

func toJWK(pub crypto.PublicKey, kid string) (jwk, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return jwk{
			Kty: "RSA",
			Kid: kid,
			Use: "sig",
			Alg: "RS256",
			N:   b64(k.N.Bytes()),
			E:   b64(big.NewInt(int64(k.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize != 256 {
			return jwk{}, fmt.Errorf("only P-256 ECDSA keys are supported (got P-%d)", k.Curve.Params().BitSize)
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		return jwk{
			Kty: "EC",
			Kid: kid,
			Use: "sig",
			Alg: "ES256",
			Crv: "P-256",
			X:   b64(k.X.FillBytes(make([]byte, size))),
			Y:   b64(k.Y.FillBytes(make([]byte, size))),
		}, nil
	default:
		return jwk{}, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

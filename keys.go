package tokenexchange

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadPrivateKey reads a PEM-encoded RSA or ECDSA private key from path and
// returns it as a [crypto.Signer] suitable for [Exchanger.PrivateKey].
func LoadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: reading private key: %w", err)
	}
	return ParsePrivateKey(data)
}

// ParsePrivateKey parses a PEM-encoded RSA or ECDSA private key. It accepts
// PKCS#1 ("RSA PRIVATE KEY"), PKCS#8 ("PRIVATE KEY"), and SEC 1 EC
// ("EC PRIVATE KEY") encodings.
func ParsePrivateKey(pemData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("tokenexchange: no PEM block found")
	}

	parsers := []func([]byte) (crypto.Signer, error){
		func(b []byte) (crypto.Signer, error) {
			return x509.ParsePKCS1PrivateKey(b)
		},
		func(b []byte) (crypto.Signer, error) {
			parsed, err := x509.ParsePKCS8PrivateKey(b)
			if err != nil {
				return nil, err
			}
			signer, ok := parsed.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("PKCS#8 key of type %T does not implement crypto.Signer", parsed)
			}
			return signer, nil
		},
		func(b []byte) (crypto.Signer, error) {
			return x509.ParseECPrivateKey(b)
		},
	}

	var parseErr error
	for _, parse := range parsers {
		signer, err := parse(block.Bytes)
		if err != nil {
			parseErr = errors.Join(parseErr, err)
			continue
		}
		return signer, nil
	}
	return nil, fmt.Errorf("tokenexchange: unable to parse private key: %w", parseErr)
}

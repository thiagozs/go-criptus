package criptus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
)

type EllipticCurve struct {
	pubKeyCurve elliptic.Curve
	privateKey  *ecdsa.PrivateKey
	publicKey   *ecdsa.PublicKey
}

func NewECDSA(opts ...ECDSAOptions) (*EllipticCurve, error) {
	params, err := newECDSAParams(opts...)
	if err != nil {
		return nil, err
	}

	if params.GetCurve() == nil {
		params.SetCurve(EllipticCurveP256)
	}

	return &EllipticCurve{
		pubKeyCurve: params.GetCurve(),
		privateKey:  new(ecdsa.PrivateKey),
	}, nil
}

func (ec *EllipticCurve) GenerateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(ec.pubKeyCurve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	ec.privateKey = privKey
	ec.publicKey = &privKey.PublicKey

	return privKey, &privKey.PublicKey, nil
}

func (ec *EllipticCurve) EncodePrivate(privKey *ecdsa.PrivateKey) (string, error) {
	encoded, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", err
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})

	return string(pemEncoded), nil
}

func (ec *EllipticCurve) EncodePublic(pubKey *ecdsa.PublicKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})

	return string(pemEncodedPub), nil
}

func (ec *EllipticCurve) DecodePrivate(pemEncodedPriv string) (*ecdsa.PrivateKey, error) {
	blockPriv, _ := pem.Decode([]byte(pemEncodedPriv))

	x509EncodedPriv := blockPriv.Bytes

	privateKey, err := x509.ParseECPrivateKey(x509EncodedPriv)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (ec *EllipticCurve) DecodePublic(pemEncodedPub string) (*ecdsa.PublicKey, error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))

	x509EncodedPub := blockPub.Bytes

	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return nil, err
	}

	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return publicKey, nil
}

func (ec *EllipticCurve) Sign(message string, privKey *ecdsa.PrivateKey) ([]byte, error) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(message))
	if err != nil {
		return nil, err
	}
	hash := hasher.Sum(nil)

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
	if err != nil {
		return nil, err
	}

	// Convert r and s values to bytes
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Concatenate r and s
	signature := append(rBytes, sBytes...)

	return signature, nil
}

func (ec *EllipticCurve) Verify(message string, signature []byte, pubKey *ecdsa.PublicKey) bool {

	if pubKey == nil {
		log.Printf("【WARN】] Public key is nil")
		return false
	}

	h := sha256.New()
	_, err := h.Write([]byte(message))
	if err != nil {
		return false
	}
	hash := h.Sum(nil)

	sigLen := len(signature)
	r, s := big.NewInt(0), big.NewInt(0)
	r.SetBytes(signature[:sigLen/2])
	s.SetBytes(signature[sigLen/2:])

	return ecdsa.Verify(pubKey, hash, r, s)
}

package criptus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"reflect"
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

func (ec *EllipticCurve) DecodePrivate(pemEncodedPriv string) (privateKey *ecdsa.PrivateKey, err error) {
	blockPriv, _ := pem.Decode([]byte(pemEncodedPriv))

	x509EncodedPriv := blockPriv.Bytes

	privateKey, err = x509.ParseECPrivateKey(x509EncodedPriv)

	return
}

func (ec *EllipticCurve) DecodePublic(pemEncodedPub string) (publicKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))

	x509EncodedPub := blockPub.Bytes

	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey = genericPublicKey.(*ecdsa.PublicKey)

	return
}

func (ec *EllipticCurve) VerifySignature(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) (signature []byte, ok bool, err error) {

	h := md5.New()

	_, err = io.WriteString(h, "This is a message to be signed and verified by ECDSA!")
	if err != nil {
		return
	}
	signhash := h.Sum(nil)

	r, s, serr := ecdsa.Sign(rand.Reader, privKey, signhash)
	if serr != nil {
		return []byte(""), false, serr
	}

	signature = r.Bytes()
	signature = append(signature, s.Bytes()...)

	ok = ecdsa.Verify(pubKey, signhash, r, s)

	return
}

func (ec *EllipticCurve) Test(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) (err error) {

	encPriv, err := ec.EncodePrivate(privKey)
	if err != nil {
		return
	}
	encPub, err := ec.EncodePublic(pubKey)
	if err != nil {
		return
	}
	priv2, err := ec.DecodePrivate(encPriv)
	if err != nil {
		return
	}
	pub2, err := ec.DecodePublic(encPub)
	if err != nil {
		return
	}

	if !reflect.DeepEqual(privKey, priv2) {
		err = errors.New("private keys do not match")
		return
	}
	if !reflect.DeepEqual(pubKey, pub2) {
		err = errors.New("public keys do not match")
		return
	}

	return
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
		log.Fatal("Public key is nil")
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

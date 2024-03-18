package criptus

import "crypto/elliptic"

type AesKeyType int
type AesModeType int
type DesKeyType int
type TripleKeyType int
type EllipticCurveType int
type RsaBitsType int

const (
	IVLength int = 16
)

// 3DES configs ----

const (
	TripleEncrypt128 TripleKeyType = iota // For 128-bit (16 bytes), typically structured as K1, K2, K1
	TripleEncrypt192                      // For 192-bit (24 bytes), structured as K1, K2, K3
)

func (a TripleKeyType) String() string {
	return [...]string{"3DES-128", "3DES-192"}[a]
}

func (a TripleKeyType) Length() int {
	// 16 bytes for 128-bit, 24 bytes for 192-bit
	return [...]int{16, 24}[a]
}

func (a TripleKeyType) Block() int {
	return 8 // 3DES block size is 8 bytes for both key lengths
}

// DES configs ----

const (
	DesEncrypt64 DesKeyType = iota
)

func (a DesKeyType) String() string {
	return [...]string{"DES-64"}[a]
}

func (a DesKeyType) Length() int {
	return [...]int{8}[a]
}

// AES configs ----

const (
	AesEncrypt128 AesKeyType = iota
	AesEncrypt192
	AesEncrypt256
)

func (a AesKeyType) String() string {
	return [...]string{"AES-128", "AES-192", "AES-256"}[a]
}

func (a AesKeyType) Length() int {
	return [...]int{16, 24, 32}[a]
}

func (a AesKeyType) Uint64() uint64 {
	return [...]uint64{128, 192, 256}[a]
}

const (
	AesModeTypeCBC AesModeType = iota // Cipher Block Chaining
	AesModeTypeCFB                    // Cipher FeedBack
	AesModeTypeCTR                    // Counter
	AesModeTypeOFB                    // Output FeedBack
	AesModeTypeECB                    // Electronic Codebook
)

func (a AesModeType) String() string {
	return [...]string{"CBC", "CFB", "CTR", "OFB", "ECB"}[a]
}

// ECDSA configs ----

const (
	EllipticCurveP224 EllipticCurveType = iota
	EllipticCurveP256
	EllipticCurveP384
	EllipticCurveP521
)

func (e EllipticCurveType) String() string {
	return [...]string{"P224", "P256", "P384", "P521"}[e]
}

func (e EllipticCurveType) Bits() int {
	return [...]int{224, 256, 384, 521}[e]
}

func (e EllipticCurveType) Curve() elliptic.Curve {
	return [...]elliptic.Curve{elliptic.P224(), elliptic.P256(),
		elliptic.P384(), elliptic.P521()}[e]
}

// RSA configs ----

const (
	RsaBits512 RsaBitsType = iota
	RsaBits1024
	RsaBits2048
	RsaBits4096
)

func (r RsaBitsType) String() string {
	return [...]string{"RSA-512", "RSA-1024", "RSA-2048", "RSA-4096"}[r]
}

func (r RsaBitsType) Bits() int {
	return [...]int{512, 1024, 2048, 4096}[r]
}

package criptus

type AesKeyType int
type AesModeType int
type DesKeyType int
type TripleKeyType int

const (
	IVLength = 16
)

const (
	TripleEncrypt TripleKeyType = iota
)

func (a TripleKeyType) String() string {
	return [...]string{"3DES"}[a]
}

func (a TripleKeyType) Length() int {
	return [...]int{24}[a]
}

func (a TripleKeyType) Block() int {
	return [...]int{8}[a]
}

const (
	DesEncrypt56 DesKeyType = iota
)

func (a DesKeyType) String() string {
	return [...]string{"DES-56"}[a]
}

func (a DesKeyType) Length() int {
	return [...]int{8}[a]
}

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

package criptus

type AESOptions func(*AESParams) error

type AESParams struct {
	specialSign     string
	key             string // Key, it is recommended to use a 5-8 digit key
	iv              string // Initial Vector 16 bytes
	aesModeType     AesModeType
	aesKeyType      AesKeyType
	aesKey          []byte
	PlainTextLength int
}

func newAESParams(opts ...AESOptions) (*AESParams, error) {
	options := &AESParams{}
	for _, opt := range opts {
		err := opt(options)
		if err != nil {
			return &AESParams{}, err
		}
	}
	return options, nil
}

func AESWithSpecialSign(specialSign string) AESOptions {
	return func(params *AESParams) error {
		params.specialSign = specialSign
		return nil
	}
}

func AESWithKey(key string) AESOptions {
	return func(params *AESParams) error {
		params.key = key
		return nil
	}
}

func AESWithIV(iv string) AESOptions {
	return func(params *AESParams) error {
		params.iv = iv
		return nil
	}
}

func AESWithAesModeType(aesModeType AesModeType) AESOptions {
	return func(params *AESParams) error {
		params.aesModeType = aesModeType
		return nil
	}
}

func AESWithAesKeyType(aesKeyType AesKeyType) AESOptions {
	return func(params *AESParams) error {
		params.aesKeyType = aesKeyType
		return nil
	}
}

func (p AESParams) GetSpecialSign() string {
	return p.specialSign
}

func (p AESParams) GetKey() string {
	return p.key
}

func (p AESParams) GetIV() string {
	return p.iv
}

func (p AESParams) GetAesModeType() AesModeType {
	return p.aesModeType
}

func (p AESParams) GetAesKeyType() AesKeyType {
	return p.aesKeyType
}

func (p AESParams) SetSpecialSign(specialSign string) {
	p.specialSign = specialSign
}

func (p *AESParams) SetKey(key string) {
	p.key = key
}

func (p *AESParams) SetIV(iv string) {
	p.iv = iv
}

func (p *AESParams) SetAesModeType(aesModeType AesModeType) {
	p.aesModeType = aesModeType
}

func (p *AESParams) SetAesKeyType(aesKeyType AesKeyType) {
	p.aesKeyType = aesKeyType
}

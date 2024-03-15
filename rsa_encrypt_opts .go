package criptus

type RSAOptions func(*RSAParams) error

type RSAParams struct {
	rsaBitsType    RsaBitsType
	publishKeyName string
	privateKeyName string
	publishKeyPath string
	privateKeyPath string
}

func newRSAParams(opts ...RSAOptions) (*RSAParams, error) {
	options := &RSAParams{}
	for _, opt := range opts {
		err := opt(options)
		if err != nil {
			return &RSAParams{}, err
		}
	}
	return options, nil
}

func RSAWithType(kind RsaBitsType) RSAOptions {
	return func(params *RSAParams) error {
		params.rsaBitsType = kind
		return nil
	}
}

func RSAWithPublishKeyName(name string) RSAOptions {
	return func(params *RSAParams) error {
		params.publishKeyName = name
		return nil
	}
}

func RSAWithPublishKeyPath(path string) RSAOptions {
	return func(params *RSAParams) error {
		params.publishKeyPath = path
		return nil
	}
}

func RSAWithPrivateKeyName(name string) RSAOptions {
	return func(params *RSAParams) error {
		params.privateKeyName = name
		return nil
	}
}

func RSAWithPrivateKeyPath(path string) RSAOptions {
	return func(params *RSAParams) error {
		params.privateKeyPath = path
		return nil
	}
}

func (p RSAParams) GetBits() RsaBitsType {
	return p.rsaBitsType
}

func (p RSAParams) GetPublishKeyName() string {
	return p.publishKeyName
}

func (p RSAParams) GetPublishKeyPath() string {
	return p.publishKeyPath
}

func (p RSAParams) GetPrivateKeyName() string {
	return p.privateKeyName
}

func (p RSAParams) GetPrivateKeyPath() string {
	return p.privateKeyPath
}

func (p *RSAParams) SetBits(bits RsaBitsType) {
	p.rsaBitsType = bits
}

func (p *RSAParams) SetPublishKeyName(name string) {
	p.publishKeyName = name
}

func (p *RSAParams) SetPublishKeyPath(path string) {
	p.publishKeyPath = path
}

func (p *RSAParams) SetPrivateKeyName(name string) {
	p.privateKeyName = name
}

func (p *RSAParams) SetPrivateKeyPath(path string) {
	p.privateKeyPath = path
}

package criptus

type DESOptions func(*DESParams) error

type DESParams struct {
	desKeyType  DesKeyType
	specialSign string
	key         string
}

func newDESParams(opts ...DESOptions) (*DESParams, error) {
	options := &DESParams{}
	for _, opt := range opts {
		err := opt(options)
		if err != nil {
			return &DESParams{}, err
		}
	}
	return options, nil
}

func DESWithKeyType(kind DesKeyType) DESOptions {
	return func(params *DESParams) error {
		params.desKeyType = kind
		return nil
	}
}

func DESWithSpecialSign(specialSign string) DESOptions {
	return func(params *DESParams) error {
		params.specialSign = specialSign
		return nil
	}
}

func DESWithKey(key string) DESOptions {
	return func(params *DESParams) error {
		params.key = key
		return nil
	}
}

func (p DESParams) GetKeyType() DesKeyType {
	return p.desKeyType
}

func (p DESParams) GetSpecialSign() string {
	return p.specialSign
}

func (p DESParams) GetKey() string {
	return p.key
}

func (p *DESParams) SetKeyType(kind DesKeyType) {
	p.desKeyType = kind
}

func (p *DESParams) SetSpecialSign(specialSign string) {
	p.specialSign = specialSign
}

func (p *DESParams) SetKey(key string) {
	p.key = key
}

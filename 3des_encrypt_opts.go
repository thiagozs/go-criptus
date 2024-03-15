package criptus

type T3DESOptions func(*T3DESParams) error

type T3DESParams struct {
	specialSign string
	key         string
	kind        TripleKeyType
}

func newT3DESParams(opts ...T3DESOptions) (*T3DESParams, error) {
	options := &T3DESParams{}
	for _, opt := range opts {
		err := opt(options)
		if err != nil {
			return &T3DESParams{}, err
		}
	}
	return options, nil
}

func T3DESWithSpecialSign(specialSign string) T3DESOptions {
	return func(params *T3DESParams) error {
		params.specialSign = specialSign
		return nil
	}
}

func T3DESWithKey(key string) T3DESOptions {
	return func(params *T3DESParams) error {
		params.key = key
		return nil
	}
}

func T3DESWithKind(kind TripleKeyType) T3DESOptions {
	return func(params *T3DESParams) error {
		params.kind = kind
		return nil
	}
}

func (p T3DESParams) GetSpecialSign() string {
	return p.specialSign
}

func (p T3DESParams) GetKey() string {
	return p.key
}

func (p T3DESParams) GetKind() TripleKeyType {
	return p.kind
}

func (p *T3DESParams) SetSpecialSign(specialSign string) {
	p.specialSign = specialSign
}

func (p *T3DESParams) SetKey(key string) {
	p.key = key
}

func (p *T3DESParams) SetKind(kind TripleKeyType) {
	p.kind = kind
}

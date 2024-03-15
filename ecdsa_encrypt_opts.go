package criptus

import "crypto/elliptic"

type ECDSAOptions func(*ECDSAParams) error

type ECDSAParams struct {
	curve EllipticCurveType
}

func newECDSAParams(opts ...ECDSAOptions) (*ECDSAParams, error) {
	options := &ECDSAParams{}
	for _, opt := range opts {
		err := opt(options)
		if err != nil {
			return &ECDSAParams{}, err
		}
	}
	return options, nil
}

func WithCurve(curve EllipticCurveType) ECDSAOptions {
	return func(params *ECDSAParams) error {
		params.curve = curve
		return nil
	}
}

func (p ECDSAParams) GetCurve() elliptic.Curve {
	return p.curve.Curve()
}

func (p *ECDSAParams) SetCurve(curve EllipticCurveType) {
	p.curve = curve
}

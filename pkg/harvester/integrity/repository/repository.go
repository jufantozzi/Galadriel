package repository

type SignCertProvider interface {
	GetSigningMaterial()
}

type ValidationCertProvider interface {
	GetValidationMaterial()
}

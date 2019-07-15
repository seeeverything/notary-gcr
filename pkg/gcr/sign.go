package gcr

import (
	"github.com/simonshyu/notary-gcr/trust"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func signImage(ref name.Reference, img v1.Image, auth authn.Authenticator, config *trust.Config) error {
	return pushTrustedReference(ref, img, auth, config)
}

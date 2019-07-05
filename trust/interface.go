package trust

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/theupdateframework/notary/client"
)

type TrustedRepository interface {
	ListTarget() ([]*client.Target, error)
	Verify() (*client.Target, error)
	TrustPush(img v1.Image) error
	SignImage(img v1.Image) error
	RevokeTag(tag string) error
}

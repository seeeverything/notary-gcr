package trust

import (
	"github.com/theupdateframework/notary/client"
)

type TrustedRepository interface {
	TrustPush() error
	TrustPull(img interface{}) error
	SignImage(img interface{}) error
	RevokeImage() error
	GetTrustedTags() ([]*client.TargetWithRole, error)
}

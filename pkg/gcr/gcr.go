package gcr

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/theupdateframework/notary/client"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	digest "github.com/opencontainers/go-digest"
	"github.com/SimonXming/notary-gcr/trust"
)

type target struct {
	name   string
	digest digest.Digest
	size   int64
}

type TrustedGcrRepository struct {
	ref     name.Reference
	auth    authn.Authenticator
	config  *trust.Config
}

func NewTrustedGcrRepository(ref name.Reference, auth authn.Authenticator) (TrustedGcrRepository, error) {
	config, err := trust.ParseConfig()
	if err != nil {
		return TrustedGcrRepository{}, err
	}
	return TrustedGcrRepository{ref, auth, config}, nil
}

func (repo *TrustedGcrRepository) GetTrustedTags() ([]*client.TargetWithRole, error) {
	fmt.Println("List tags...")
	targets, err := listTargets(repo.ref, repo.auth, repo.config)
	if err != nil {
		fmt.Printf("Error ... %s", err)
		return nil, err
	}
	return targets, nil
}

func (repo *TrustedGcrRepository) TrustPush(img v1.Image) {
	err := pushImage(repo.ref, img, repo.auth)
	if err != nil {
		fmt.Printf("Error ... %s", err)
		return
	}
	pushTrustedReference(repo.ref, img, repo.auth, repo.config)
	// return PushTrustedReference(repo.ref, img, repo.auth)
}


func (repo *TrustedGcrRepository) TrustPull(des string) {
	fmt.Println("Pulling..." + des)
	trustedPull(repo.ref, repo.auth, repo.config)
}

// Sign a locally tagged image
func (repo *TrustedGcrRepository) SignImage(img v1.Image) {
	fmt.Println("Signing image...")
	signImage(repo.ref, img, repo.auth, repo.config)
}

func (repo *TrustedGcrRepository) RevokeTag(tag string) {
	fmt.Println("Revoke image...")
	revokeImage(repo.ref, tag, repo.auth, repo.config)
}

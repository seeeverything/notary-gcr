package gcr

import (
	"github.com/simonshyu/notary-gcr/trust"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary/client"
)

type TrustedGcrRepository struct {
	ref    name.Reference
	auth   authn.Authenticator
	config *trust.Config
}

func NewTrustedGcrRepository(ref name.Reference, auth authn.Authenticator) (TrustedGcrRepository, error) {
	config, err := trust.ParseConfig()
	if err != nil {
		log.Errorf("failed to parse config: %s", err)
		return TrustedGcrRepository{}, err
	}
	return TrustedGcrRepository{ref, auth, config}, nil
}

func (repo *TrustedGcrRepository) ListTarget() ([]*client.Target, error) {
	targets, err := listTargets(repo.ref, repo.auth, repo.config)
	if err != nil {
		log.Errorf("failed to list targets: %s", err)
		return nil, err
	}
	return targets, nil
}

func (repo *TrustedGcrRepository) TrustPush(img v1.Image) error {
	err := pushImage(repo.ref, img, repo.auth)
	if err != nil {
		log.Errorf("failed to push image: %s", err)
		return err
	}
	return pushTrustedReference(repo.ref, img, repo.auth, repo.config)
}

func (repo *TrustedGcrRepository) Verify() (*client.Target, error) {
	target, err := getTrustedTarget(repo.ref, repo.auth, repo.config)
	if err != nil {
		log.Errorf("failed to verify repository: %s", err)
		return nil, err
	}
	return target, nil
}

func (repo *TrustedGcrRepository) SignImage(img v1.Image) error {
	err := signImage(repo.ref, img, repo.auth, repo.config)
	if err != nil {
		log.Errorf("failed to sign image: %s", err)
		return err
	}
	return nil
}

func (repo *TrustedGcrRepository) RevokeTag(tag string) error {
	err := revokeImage(repo.ref, tag, repo.auth, repo.config)
	if err != nil {
		log.Errorf("failed to revoke trusted repository: %s", err)
		return err
	}
	return nil
}

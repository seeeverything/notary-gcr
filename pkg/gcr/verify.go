package gcr

import (
	"github.com/SimonXming/notary-gcr/trust"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/tuf/data"
)

func getTrustedTarget(ref name.Reference, auth authn.Authenticator, config *trust.Config) (*client.Target, error) {
	repoInfo := ref.Context().Registry
	notaryRepo, err := trust.GetNotaryRepository(ref, auth, &repoInfo, config)
	if err != nil {
		return nil, errors.Wrap(err, "error establishing connection to trust repository")
	}
	tag, err := name.NewTag(ref.String(), name.StrictValidation)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't parse tag from repository name")
	}

	t, err := notaryRepo.GetTargetByName(tag.Identifier(), trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return nil, trust.NotaryError(ref.Name(), err)
	}
	// Only get the tag if it's in the top level targets role or the releases delegation role
	// ignore it if it's in any other delegation roles
	if t.Role != trust.ReleasesRole && t.Role != data.CanonicalTargetsRole {
		return nil, trust.NotaryError(ref.Name(), errors.Errorf("No trust data for %s", tag.Identifier()))
	}

	log.Debugf("retrieving target for %s role", t.Role)
	return &t.Target, nil
}

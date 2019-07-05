package gcr

import (
	"fmt"

	"github.com/SimonXming/notary-gcr/trust"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/tuf/data"
)

func revokeImage(ref name.Reference, tag string, auth authn.Authenticator, config *trust.Config) error {
	repoInfo := ref.Context().Registry
	notaryRepo, err := trust.GetNotaryRepository(ref, auth, &repoInfo, config)
	if err != nil {
		return errors.Wrap(err, "error establishing connection to trust repository")
	}

	if err = clearChangeList(notaryRepo); err != nil {
		return err
	}
	defer clearChangeList(notaryRepo)
	if err := revokeSignature(notaryRepo, tag); err != nil {
		return errors.Wrapf(err, "could not remove signature for %s", tag)
	}
	log.Infof("Successfully deleted signature for %s\n", tag)
	return nil
}

func revokeSignature(notaryRepo client.Repository, tag string) error {
	if tag != "" {
		// Revoke signature for the specified tag
		if err := revokeSingleSig(notaryRepo, tag); err != nil {
			return err
		}
	} else {
		// revoke all signatures for the image, as no tag was given
		if err := revokeAllSigs(notaryRepo); err != nil {
			return err
		}
	}

	//  Publish change
	return notaryRepo.Publish()
}

func revokeSingleSig(notaryRepo client.Repository, tag string) error {
	releasedTargetWithRole, err := notaryRepo.GetTargetByName(tag, trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return err
	}
	releasedTarget := releasedTargetWithRole.Target
	return getSignableRolesForTargetAndRemove(releasedTarget, notaryRepo)
}

func revokeAllSigs(notaryRepo client.Repository) error {
	releasedTargetWithRoleList, err := notaryRepo.ListTargets(trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return err
	}

	if len(releasedTargetWithRoleList) == 0 {
		return fmt.Errorf("no signed tags to remove")
	}

	// we need all the roles that signed each released target so we can remove from all roles.
	for _, releasedTargetWithRole := range releasedTargetWithRoleList {
		// remove from all roles
		if err := getSignableRolesForTargetAndRemove(releasedTargetWithRole.Target, notaryRepo); err != nil {
			return err
		}
	}
	return nil
}

// get all the roles that signed the target and removes it from all roles.
func getSignableRolesForTargetAndRemove(releasedTarget client.Target, notaryRepo client.Repository) error {
	signableRoles, err := trust.GetSignableRoles(notaryRepo, &releasedTarget)
	if err != nil {
		return err
	}
	// remove from all roles
	return notaryRepo.RemoveTarget(releasedTarget.Name, signableRoles...)
}

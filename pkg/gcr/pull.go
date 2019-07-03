package gcr

import (
	"fmt"
	"os"
	"path/filepath"
	"encoding/hex"

	"github.com/sirupsen/logrus"
	"github.com/pkg/errors"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/client"
	digest "github.com/opencontainers/go-digest"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/SimonXming/notary-gcr/trust"
)


func trustedPull(ref name.Reference, auth authn.Authenticator, config *trust.Config) error {
	refs, err := getTrustedPullTargets(ref, auth, config)
	if err != nil {
		fmt.Println("error " + err.Error())
		return err
	}

	for i, r := range refs {
		displayTag := r.name
		if displayTag != "" {
			displayTag = ":" + displayTag
		}
		fmt.Fprintf(os.Stderr, "Pull (%d of %d): %s%s@%s\n", i+1, len(refs), ref.Context().Name(), displayTag, r.digest)

		// TODO: Complete test cases
		trustedRef := ref.Context().Name() + "@" + r.digest.String()
		trustedImgRef, err := name.ParseReference(trustedRef, name.WeakValidation)
		if err != nil {
			logrus.Errorf("failed to resolve name: %s", err)
			return err
		}

		imageOpts := []remote.ImageOption{
			remote.WithAuth(auth),
			// remote.WithTransport(http.DefaultTransport),
		}
		image, err := remote.Image(trustedImgRef, imageOpts...)
		if err != nil {
			logrus.Errorf("failed to locate remote image: %s", err)
			return err
		}

		ociFormat(ref, image)
	}
	return nil
}

func ociFormat(ref name.Reference, image v1.Image) {
	tag, err := name.NewTag(ref.String(), name.WeakValidation)
	if err != nil {
		logrus.Errorf("failed to construct tag reference: %s", err)
		os.Exit(1)
		return
	}

	err = tarball.WriteToFile(filepath.Join(".", "image.tar"), tag, image)
	if err != nil {
		logrus.Errorf("failed to write OCI image: %s", err)
		os.Exit(1)
		return
	}
}

func getTrustedPullTargets(ref name.Reference, auth authn.Authenticator, config *trust.Config) ([]target, error) {
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

	logrus.Debugf("retrieving target for %s role", t.Role)
	r, err := convertTarget(t.Target)
	return []target{r}, err
}

func convertTarget(t client.Target) (target, error) {
	h, ok := t.Hashes["sha256"]
	if !ok {
		return target{}, errors.New("no valid hash, expecting sha256")
	}
	return target{
		name:   t.Name,
		digest: digest.NewDigestFromHex("sha256", hex.EncodeToString(h)),
		size:   t.Length,
	}, nil
}

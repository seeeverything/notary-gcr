package gcr

import (
	"encoding/hex"
	"sort"
	"time"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/pkg/errors"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/SimonXming/notary-gcr/trust"
)

func pushImage(ref name.Reference, img v1.Image, auth authn.Authenticator) error {
	defaultRoundTripper := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}
	err := remote.Write(ref, img, auth, defaultRoundTripper)
	if err != nil {
		logrus.Errorf("failed to push image: %s", err)
		return err
	}
	return nil
}

func pushTrustedReference(ref name.Reference, img v1.Image, auth authn.Authenticator, config *trust.Config) error {
	// If it is a trusted push we would like to find the target entry which match the
	// tag provided in the function and then do an AddTarget later.
	target := &client.Target{}

	digest, err := img.Digest()
	if err != nil {
		logrus.Errorf("failed to get img.Digest: %s", err)
		return err
	}
	h, err := hex.DecodeString(digest.Hex)
	if err != nil {
		logrus.Errorf("failed to decode digest.Hex: %s", err)
		return err
	}
	target.Name = ref.Identifier()
	target.Hashes = data.Hashes{digest.Algorithm: h}
	manifest, _ := img.RawManifest()
	pushResultSize := len(manifest)
	target.Length = int64(pushResultSize)

	if target == nil {
		return errors.Errorf("no targets found, please provide a specific tag in order to sign it")
	}

	repoInfo := ref.Context().Registry
	repo, err := trust.GetNotaryRepository(ref, auth, &repoInfo, config)
	if err != nil {
		logrus.Errorf("failed to get notary repository %s", err)
		return err
	}
	logrus.Info("Signing and pushing trust metadata")
	_, err = repo.ListTargets()

	switch err.(type) {
	case client.ErrRepoNotInitialized, client.ErrRepositoryNotExist:
		keys := repo.GetCryptoService().ListKeys(data.CanonicalRootRole)
		var rootKeyID string
		// always select the first root key
		if len(keys) > 0 {
			sort.Strings(keys)
			rootKeyID = keys[0]
		} else {
			rootPublicKey, err := repo.GetCryptoService().Create(data.CanonicalRootRole, "", data.ECDSAKey)
			if err != nil {
				logrus.Errorf("error: %s", err)
			}
			rootKeyID = rootPublicKey.ID()
		}
		// Initialize the notary repository with a remotely managed snapshot key
		if err := repo.Initialize([]string{rootKeyID}, data.CanonicalSnapshotRole); err != nil {
			logrus.Errorf("error: %s", err)
		}

		logrus.Infof("Finished initializing %s\n", ref.Context().Name())
		err = repo.AddTarget(target, data.CanonicalTargetsRole)
	case nil:
		// already initialized and we have successfully downloaded the latest metadata
		err = addTargetToAllSignableRoles(repo, target)
	default:
		return trust.NotaryError(repoInfo.Name(), err)
	}

	if err == nil {
		err = repo.Publish()
	}

	if err != nil {
		logrus.Infof("failed to sign: %s", err)
	}
	logrus.Infof("Successfully signed %s:%s\n", ref.Context().Name(), ref.Identifier())
	return nil
}

// addTargetToAllSignableRoles attempts to add the image target to all the top level delegation roles we can
// (based on whether we have the signing key and whether the role's path allows
// us to).
// If there are no delegation roles, we add to the targets role.
func addTargetToAllSignableRoles(repo client.Repository, target *client.Target) error {
	signableRoles, err := trust.GetSignableRoles(repo, target)
	if err != nil {
		return err
	}

	return repo.AddTarget(target, signableRoles...)
}

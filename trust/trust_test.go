package trust

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/passphrase"
	"github.com/theupdateframework/notary/trustpinning"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/google/go-containerregistry/pkg/name"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestNotaryServer(t *testing.T) {
	ref, _ := name.ParseReference("dockerhub.com/foo/image:latest", name.WeakValidation)
	repoInfo := ref.Context().Registry
	notaryServer, err := Server("https://127.0.0.1:4443", &repoInfo)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(notaryServer, "https://127.0.0.1:4443"))

	ref, _ = name.ParseReference("dockerhub.com/foo/image:latest", name.WeakValidation)
	repoInfo = ref.Context().Registry
	notaryServer, err = Server("", &repoInfo)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(notaryServer, "https://dockerhub.com"))

	ref, _ = name.ParseReference("alpine:latest", name.WeakValidation)
	repoInfo = ref.Context().Registry
	notaryServer, err = Server("", &repoInfo)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(notaryServer, "https://notary.docker.io"))

	ref, _ = name.ParseReference("alpine:latest", name.WeakValidation)
	repoInfo = ref.Context().Registry
	notaryServer, err = Server("http://127.0.0.1:4443", &repoInfo)
	assert.Error(t, err, "valid https URL required for trust server, got http://127.0.0.1:4443")
}

func TestCertificateDirectory(t *testing.T) {
	certDir, err := certificateDirectory("~/.notary", "https://127.0.0.1:4443")
	assert.NilError(t, err)
	assert.Check(t, is.Equal(certDir, "~/.notary/tls/127.0.0.1:4443"))
}

func TestGetTrustDirectory(t *testing.T) {
	trustDir := getTrustDirectory("~/.notary")
	assert.Check(t, is.Equal(trustDir, "~/.notary/trust"))
}

func TestGetPassphraseRetriever(t *testing.T) {
	// Check that root is cached
	retriever := GetPassphraseRetriever(os.Stdin, os.Stderr, "root_passphrase", "repo_passphrase")
	passphrase, giveup, err := retriever("key", data.CanonicalRootRole.String(), false, 0)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(false, giveup))
	assert.Check(t, is.Equal(passphrase, "root_passphrase"))
}

func TestGetSignableRolesError(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "notary-test-")
	assert.NilError(t, err)
	defer os.RemoveAll(tmpDir)

	notaryRepo, err := client.NewFileCachedRepository(tmpDir, "gun", "https://localhost", nil, passphrase.ConstantRetriever("password"), trustpinning.TrustPinConfig{})
	assert.NilError(t, err)
	target := client.Target{}
	_, err = GetSignableRoles(notaryRepo, &target)
	assert.Error(t, err, "client is offline")
}
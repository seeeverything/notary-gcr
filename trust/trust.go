package trust

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/go-connections/tlsconfig"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/passphrase"
	"github.com/theupdateframework/notary/storage"
	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/trustpinning"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/signed"
)

var (
	// ReleasesRole is the role named "releases"
	ReleasesRole = data.RoleName(path.Join(data.CanonicalTargetsRole.String(), "releases"))
	// ActionsPullOnly defines the actions for read-only interactions with a Notary Repository
	ActionsPullOnly = []string{"pull"}
	// ActionsPushAndPull defines the actions for read-write interactions with a Notary Repository
	ActionsPushAndPull = []string{"pull", "push"}
	// NotaryServer is the endpoint serving the Notary trust server
	NotaryServer = "https://notary.docker.io"
)

// Server returns the base URL for the trust server.
func Server(serverUrl string, repoInfo *name.Registry) (string, error) {
	if serverUrl != "" {
		urlObj, err := url.Parse(serverUrl)
		if err != nil || urlObj.Scheme != "https" {
			return "", errors.Errorf("valid https URL required for trust server, got %s", serverUrl)
		}
		return serverUrl, nil
	}
	if repoInfo.RegistryStr() == name.DefaultRegistry {
		return NotaryServer, nil
	}

	return "https://" + repoInfo.Name(), nil
}

// GetNotaryRepository returns a NotaryRepository which stores all the
// information needed to operate on a notary repository.
// It creates an HTTP transport providing authentication support.
func GetNotaryRepository(ref name.Reference, auth authn.Authenticator, repoInfo *name.Registry, config *Config) (client.Repository, error) {
	server, err := Server(config.ServerUrl, repoInfo)
	if err != nil {
		return nil, err
	}

	var cfg = tlsconfig.ClientDefault()
	if repoInfo.Scheme() == "https" {
		cfg.InsecureSkipVerify = true
	}

	// Get certificate base directory
	certDir, err := certificateDirectory(config.RootPath, server)
	if err != nil {
		return nil, err
	}
	log.Infof("reading certificate directory: %s \n", certDir)

	if err := readCertsDirectory(cfg, certDir); err != nil {
		return nil, err
	}

	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     cfg,
		DisableKeepAlives:   true,
	}

	repo := ref.Context()
	scopes := []string{repo.Scope(transport.PushScope)}
	tr, err := transport.New(repo.Registry, auth, base, scopes)
	if err != nil {
		return nil, err
	}
	ecrURIwithoutTag := strings.Split(fmt.Sprintf("%s",ref), ":")[0]

	log.Infof("using ref as certificate directory: %s \n", fmt.Sprintf("%s", ecrURIwithoutTag))

	return client.NewFileCachedRepository(
		getTrustDirectory(config.RootPath),
		data.GUN(fmt.Sprintf("%s", ecrURIwithoutTag)),
		server,
		tr,
		GetPassphraseRetriever(os.Stdin, os.Stderr, config.RootPassphrase, config.RepositoryPassphrase),
		trustpinning.TrustPinConfig{})
}

// GetSignableRoles returns a list of roles for which we have valid signing
// keys, given a notary repository and a target
func GetSignableRoles(repo client.Repository, target *client.Target) ([]data.RoleName, error) {
	var signableRoles []data.RoleName

	// translate the full key names, which includes the GUN, into just the key IDs
	allCanonicalKeyIDs := make(map[string]struct{})
	for fullKeyID := range repo.GetCryptoService().ListAllKeys() {
		allCanonicalKeyIDs[path.Base(fullKeyID)] = struct{}{}
	}

	allDelegationRoles, err := repo.GetDelegationRoles()
	if err != nil {
		return signableRoles, err
	}

	// if there are no delegation roles, then just try to sign it into the targets role
	if len(allDelegationRoles) == 0 {
		signableRoles = append(signableRoles, data.CanonicalTargetsRole)
		return signableRoles, nil
	}

	// there are delegation roles, find every delegation role we have a key for, and
	// attempt to sign into into all those roles.
	for _, delegationRole := range allDelegationRoles {
		// We do not support signing any delegation role that isn't a direct child of the targets role.
		// Also don't bother checking the keys if we can't add the target
		// to this role due to path restrictions
		if path.Dir(delegationRole.Name.String()) != data.CanonicalTargetsRole.String() || !delegationRole.CheckPaths(target.Name) {
			continue
		}

		for _, canonicalKeyID := range delegationRole.KeyIDs {
			if _, ok := allCanonicalKeyIDs[canonicalKeyID]; ok {
				signableRoles = append(signableRoles, delegationRole.Name)
				break
			}
		}
	}

	if len(signableRoles) == 0 {
		return signableRoles, errors.Errorf("no valid signing keys for delegation roles")
	}

	return signableRoles, nil

}

// GetPassphraseRetriever returns a passphrase retriever that utilizes configuration
func GetPassphraseRetriever(in io.Reader, out io.Writer, rootPassphrase string, repoPassphrase string) notary.PassRetriever {
	aliasMap := map[string]string{
		"root":     "root",
		"snapshot": "repository",
		"targets":  "repository",
		"default":  "repository",
	}

	baseRetriever := passphrase.PromptRetrieverWithInOut(in, out, aliasMap)
	env := map[string]string{
		"root":     rootPassphrase,
		"snapshot": repoPassphrase,
		"targets":  repoPassphrase,
		"default":  repoPassphrase,
	}

	return func(keyName string, alias string, createNew bool, numAttempts int) (string, bool, error) {
		if v := env[alias]; v != "" {
			return v, numAttempts > 1, nil
		}
		// For non-root roles, we can also try the "default" alias if it is specified
		if v := env["default"]; v != "" && alias != data.CanonicalRootRole.String() {
			return v, numAttempts > 1, nil
		}
		return baseRetriever(keyName, alias, createNew, numAttempts)
	}
}

// getTrustDirectory returns the base trust directory name
func getTrustDirectory(configDir string) string {
	return filepath.Join(configDir, "trust")
}

// certificateDirectory returns the directory containing
// TLS certificates for the given server. An error is
// returned if there was an error parsing the server string.
func certificateDirectory(configDir string, server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "tls", u.Host), nil
}

// readCertsDirectory reads the directory for TLS certificates
// including roots and certificate pairs and updates the
// provided TLS configuration.
func readCertsDirectory(tlsConfig *tls.Config, directory string) error {
	fs, err := ioutil.ReadDir(directory)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	for _, f := range fs {
		if strings.HasSuffix(f.Name(), ".crt") {
			if tlsConfig.RootCAs == nil {
				systemPool, err := tlsconfig.SystemCertPool()
				if err != nil {
					return fmt.Errorf("unable to get system cert pool: %v", err)
				}
				tlsConfig.RootCAs = systemPool
			}
			log.Debugf("crt: %s", filepath.Join(directory, f.Name()))
			data, err := ioutil.ReadFile(filepath.Join(directory, f.Name()))
			if err != nil {
				return err
			}
			tlsConfig.RootCAs.AppendCertsFromPEM(data)
		}
		if strings.HasSuffix(f.Name(), ".cert") {
			certName := f.Name()
			keyName := certName[:len(certName)-5] + ".key"
			log.Debugf("cert: %s", filepath.Join(directory, f.Name()))
			if !hasFile(fs, keyName) {
				return fmt.Errorf("missing key %s for client certificate %s. Note that CA certificates should use the extension .crt", keyName, certName)
			}
			cert, err := tls.LoadX509KeyPair(filepath.Join(directory, certName), filepath.Join(directory, keyName))
			if err != nil {
				return err
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}
		if strings.HasSuffix(f.Name(), ".key") {
			keyName := f.Name()
			certName := keyName[:len(keyName)-4] + ".cert"
			log.Debugf("key: %s", filepath.Join(directory, f.Name()))
			if !hasFile(fs, certName) {
				return fmt.Errorf("Missing client certificate %s for key %s", certName, keyName)
			}
		}
	}

	return nil
}

func hasFile(files []os.FileInfo, name string) bool {
	for _, f := range files {
		if f.Name() == name {
			return true
		}
	}
	return false
}

// NotaryError formats an error message received from the notary service
func NotaryError(repoName string, err error) error {
	switch err.(type) {
	case *json.SyntaxError:
		log.Debugf("Notary syntax error: %s", err)
		return errors.Errorf("Error: no trust data available for remote repository %s. Try running notary server and setting DOCKER_CONTENT_TRUST_SERVER to its HTTPS address?", repoName)
	case signed.ErrExpired:
		return errors.Errorf("Error: remote repository %s out-of-date: %v", repoName, err)
	case trustmanager.ErrKeyNotFound:
		return errors.Errorf("Error: signing keys for remote repository %s not found: %v", repoName, err)
	case storage.NetworkError:
		return errors.Errorf("Error: error contacting notary server: %v", err)
	case storage.ErrMetaNotFound:
		return errors.Errorf("Error: trust data missing for remote repository %s or remote repository not found: %v", repoName, err)
	case trustpinning.ErrRootRotationFail, trustpinning.ErrValidationFail, signed.ErrInvalidKeyType:
		return errors.Errorf("Warning: potential malicious behavior - trust data mismatch for remote repository %s: %v", repoName, err)
	case signed.ErrNoKeys:
		return errors.Errorf("Error: could not find signing keys for remote repository %s, or could not decrypt signing key: %v", repoName, err)
	case signed.ErrLowVersion:
		return errors.Errorf("Warning: potential malicious behavior - trust data version is lower than expected for remote repository %s: %v", repoName, err)
	case signed.ErrRoleThreshold:
		return errors.Errorf("Warning: potential malicious behavior - trust data has insufficient signatures for remote repository %s: %v", repoName, err)
	case client.ErrRepositoryNotExist:
		return errors.Errorf("Error: remote trust data does not exist for %s: %v", repoName, err)
	case signed.ErrInsufficientSignatures:
		return errors.Errorf("Error: could not produce valid signature for %s.  If Yubikey was used, was touch input provided?: %v", repoName, err)
	case client.ErrNoSuchTarget:
		return errors.Errorf("Error: remote trust target does not exist for %s: %v", repoName, err)
	}

	return err
}

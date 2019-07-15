package trust

import (
	"os"
	"io/ioutil"
	"path/filepath"
	"testing"
	log "github.com/sirupsen/logrus"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestParseFullConfig(t *testing.T) {
	configFile, err := ioutil.TempFile("", "gcr-config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(configFile.Name())
	if _, err := configFile.Write([]byte(`{"server_url": "https://127.0.0.1:4443", "root_passphrase": "root", "repository_passphrase": "repo"}`)); err != nil {
		log.Fatal(err)
	}

	os.Setenv("NOTARY_CONFIG_DIR", filepath.Dir(configFile.Name()))
	os.Setenv("NOTARY_CONFIG_FILENAME", filepath.Base(configFile.Name()))

	conf, err:= ParseConfig()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(conf.ServerUrl, "https://127.0.0.1:4443"))
	assert.Check(t, is.Equal(conf.RootPassphrase, "root"))
	assert.Check(t, is.Equal(conf.RepositoryPassphrase, "repo"))

	if err := configFile.Close(); err != nil {
		log.Fatal(err)
	}
}

func TestParsePartialConfig(t *testing.T) {
	configFile, err := ioutil.TempFile("", "gcr-config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(configFile.Name())
	if _, err := configFile.Write([]byte(`{"root_passphrase": "root", "repository_passphrase": "repo"}`)); err != nil {
		log.Fatal(err)
	}

	os.Setenv("NOTARY_CONFIG_DIR", filepath.Dir(configFile.Name()))
	os.Setenv("NOTARY_CONFIG_FILENAME", filepath.Base(configFile.Name()))

	conf, err:= ParseConfig()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(conf.ServerUrl, ""))
	assert.Check(t, is.Equal(conf.RootPassphrase, "root"))
	assert.Check(t, is.Equal(conf.RepositoryPassphrase, "repo"))
	assert.Check(t, is.Equal(conf.RootPath, filepath.Dir(configFile.Name())))

	configFile.Truncate(0)
	configFile.Seek(0, 0)

	if _, err := configFile.Write([]byte(`{"server_url": "https://127.0.0.1:4443", "repository_passphrase": "repo"}`)); err != nil {
		log.Fatal(err)
	}
	conf, err = ParseConfig()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(conf.ServerUrl, "https://127.0.0.1:4443"))
	assert.Check(t, is.Equal(conf.RootPassphrase, ""))
	assert.Check(t, is.Equal(conf.RepositoryPassphrase, "repo"))
	assert.Check(t, is.Equal(conf.RootPath, filepath.Dir(configFile.Name())))

	if err := configFile.Close(); err != nil {
		log.Fatal(err)
	}
}
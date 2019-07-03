package trust

import (
	"os"
	"io/ioutil"
	"encoding/json"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

type Config struct {
	RootPath             string
	ServerUrl            string `json:"server_url"`
	RootPassphrase       string `json:"root_passphrase"`
	RepositoryPassphrase string `json:"repository_passphrase"`
}

const (
	// configDir is the root path for configuration
	configFileDir = ".notary"
	configFileName = "gcr-config.json"
)

var (
	configDir = os.Getenv("NOTARY_CONFIG_DIR")
	notaryServerUrl = "https://10.160.23.6:4443"
	rootPassphrase = "123456789"
	repositoryPassphrase = "123456789"
)

func init() {
	if configDir == "" {
		configDir = filepath.Join(os.Getenv("HOME"), configFileDir)
	}
	if !filepath.IsAbs(configDir) {
		logrus.Warnf("config directory %s maybe wrong, not absolute path", configDir)
	}
}

func ParseConfig() (*Config, error) {
	configFilePath := filepath.Join(configDir, configFileName)
	configFile, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	c := new(Config)
	err = json.Unmarshal([]byte(configFile), c)
	if err != nil {
		return nil, err
	}

	c.RootPath = configDir
	return c, nil
}
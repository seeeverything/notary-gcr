package trust

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

type Config struct {
	RootPath             string
	ServerUrl            string `json:"server_url"`
	RootPassphrase       string `json:"root_passphrase"`
	RepositoryPassphrase string `json:"repository_passphrase"`
}

const (
	// configDir is the root path for configuration
	configFileDir  = ".notary"
	configFileName = "gcr-config.json"
)

var (
	configDir = os.Getenv("NOTARY_CONFIG_DIR")
)

func init() {
	if configDir == "" {
		configDir = filepath.Join(os.Getenv("HOME"), configFileDir)
	}
	if !filepath.IsAbs(configDir) {
		log.Warnf("config directory %s maybe wrong, not absolute path", configDir)
	}
}

// ParseConfig read configfile (${configDir}/${configFileName})
// returns a Config object and error.
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

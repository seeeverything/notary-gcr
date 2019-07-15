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
	configDirEnv          = "NOTARY_CONFIG_DIR"
	configFileNameEnv     = "NOTARY_CONFIG_FILENAME"
	defaultConfigFileName = "gcr-config.json"
)

// ParseConfig read configfile (${configDir}/${configFileName})
// returns a Config object and error.
func ParseConfig() (*Config, error) {
	configDir := os.Getenv(configDirEnv)
	if configDir == "" {
		configDir = filepath.Join(os.Getenv("HOME"), ".notary")
	}
	if !filepath.IsAbs(configDir) {
		log.Warnf("config directory %s maybe wrong, not absolute path", configDir)
	}

	configFileName := os.Getenv(configFileNameEnv)
	if configFileName == "" {
		configFileName = defaultConfigFileName
	}

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

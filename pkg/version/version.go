package version

import (
	"io/ioutil"
	"strings"
	"sync"
)

const (
	collectorTag = "latest"

	versionFile = "VERSION"
)

var (
	version string
	err     error
	once    sync.Once
)

// GetVersion returns the tag of Prevent
func GetVersion() (string, error) {
	once.Do(func() {
		var versionBytes []byte
		versionBytes, err = ioutil.ReadFile(versionFile)
		if err != nil {
			return
		}
		version = strings.TrimSpace(string(versionBytes))
	})
	return version, err
}

// GetCollectorVersion returns the currenty collector tag
func GetCollectorVersion() string {
	return collectorTag
}

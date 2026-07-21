package subscriptionconverter

import (
	"encoding/json"
	"fmt"
	"runtime"
)

var (
	gitVersion = "v0.0.0-main"
	gitCommit  = "unknown"
	buildDate  = "1970-01-01T00:00:00Z"
)

type Version struct {
	GitVersion string `json:"git_version"`
	GitCommit  string `json:"git_commit"`
	BuildDate  string `json:"build_date"`
	GoVersion  string `json:"go_version"`
	Compiler   string `json:"compiler"`
	Platform   string `json:"platform"`
}

func GetVersion() Version {
	return Version{
		GitVersion: gitVersion,
		GitCommit:  gitCommit,
		BuildDate:  buildDate,
		GoVersion:  runtime.Version(),
		Compiler:   runtime.Compiler,
		Platform:   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func (v Version) String() string {
	data, _ := json.MarshalIndent(v, "", "  ")
	return string(data)
}

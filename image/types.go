package image

import (
	"encoding/json"
	"github.com/opencontainers/go-digest"
	"time"
)

type HealthConfig struct {
	Test []string `json:",omitempty"`

	// Zero means to inherit. Durations are expressed as integer nanoseconds.
	Interval    time.Duration `json:",omitempty"` // Interval is the time to wait between checks.
	Timeout     time.Duration `json:",omitempty"` // Timeout is the time to wait before considering the check to have hung.
	StartPeriod time.Duration `json:",omitempty"` // The start period for the container to initialize before the retries starts to count down.

	Retries int `json:",omitempty"`
}

type Config struct {
	Hostname        string              // Hostname
	Domainname      string              // Domainname
	User            string              // User that will run the command(s) inside the container, also support user:group
	AttachStdin     bool                // Attach the standard input, makes possible user interaction
	AttachStdout    bool                // Attach the standard output
	AttachStderr    bool                // Attach the standard error
	Tty             bool                // Attach standard streams to a tty, including stdin if it is not closed.
	OpenStdin       bool                // Open stdin
	StdinOnce       bool                // If true, close stdin after the 1 attached client disconnects.
	Env             []string            // List of environment variable to set in the container
	Volumes         map[string]struct{} // List of volumes (mounts) used for the container
	MacAddress      string              `json:",omitempty"` // Mac Address of the container
	Image           string              // Name of the image as it was passed by the operator (e.g. could be symbolic)
	Labels          map[string]string   // List of labels set to this container\\
	Entrypoint      StrSlice            // Entrypoint to run when starting the container
	WorkingDir      string              // Current directory (PWD) in the command will be launched
	Cmd             StrSlice            // Command to run when starting the container
	ArgsEscaped     bool                `json:",omitempty"` // True if command is already escaped (Windows specific)
	Healthcheck     *HealthConfig       `json:",omitempty"` // Healthcheck describes how to check the container is healthy
	StopSignal      string              `json:",omitempty"` // Signal to stop a container
	StopTimeout     *int                `json:",omitempty"` // Timeout (in seconds) to stop a container
	NetworkDisabled bool                `json:",omitempty"` // Is network disabled
}

type Image struct {
	RootFS          *RootFS `json:"rootfs,omitempty"`
	Config          *Config `json:"config,omitempty"`
	ContainerConfig *Config `json:"container_config,omitempty"`
}

type RootFS struct {
	Type    string          `json:"type"`
	DiffIDs []digest.Digest `json:"diff_ids,omitempty"`
}

// StrSlice represents a string or an array of strings.
// We need to override the json decoder to accept both options.
type StrSlice []string

// UnmarshalJSON decodes the byte slice whether it's a string or an array of
// strings. This method is needed to implement json.Unmarshaler.
func (e *StrSlice) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		// With no input, we preserve the existing value by returning nil and
		// leaving the target alone. This allows defining default values for
		// the type.
		return nil
	}

	p := make([]string, 0, 1)
	if err := json.Unmarshal(b, &p); err != nil {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		p = append(p, s)
	}

	*e = p
	return nil
}

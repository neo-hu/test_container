package config

import (
	"golang.org/x/sys/unix"
	"path/filepath"
)

type Mounts []Mount

func (n Mounts) Contains(t string) bool {
	for _, ns := range n {
		if ns.Type == t {
			return true
		}
	}
	return false
}

const (
	// EXT_COPYUP is a directive to copy up the contents of a directory when
	// a tmpfs is mounted over it.
	EXT_COPYUP = 1 << iota
)

type LibMount struct {
	// Source path for the mount.
	Source string `json:"source"`

	// Destination path for the mount inside the container.
	Destination string `json:"destination"`

	// Device the mount is for.
	Device string `json:"device"`

	// Mount flags.
	Flags int `json:"flags"`

	// Propagation Flags
	PropagationFlags []int `json:"propagation_flags"`

	// Mount data applied to the mount.
	Data string `json:"data"`

	// Relabel source if set, "z" indicates shared, "Z" indicates unshared.
	Relabel string `json:"relabel"`

	// Extensions are additional flags that are specific to runc.
	Extensions int `json:"extensions"`
}

func createMount(cwd string, m Mount) *LibMount {
	flags, pgflags, data, ext := parseMountOptions(m.Options)
	source := m.Source
	device := m.Type
	if flags&unix.MS_BIND != 0 {
		if device == "" {
			device = "bind"
		}
		if !filepath.IsAbs(source) {
			source = filepath.Join(cwd, m.Source)
		}
	}
	return &LibMount{
		Device:           device,
		Source:           source,
		Destination:      m.Destination,
		Data:             data,
		Flags:            flags,
		PropagationFlags: pgflags,
		Extensions:       ext,
	}
}

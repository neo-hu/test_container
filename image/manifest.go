package image

import (
	"github.com/opencontainers/go-digest"
)

const (
	MediaTypeManifest    = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeImageConfig = "application/vnd.docker.container.image.v1+json"
)

type Descriptor struct {
	// MediaType describe the type of the content. All text based formats are
	// encoded as utf-8.
	MediaType string `json:"mediaType,omitempty"`

	// Size in bytes of content.
	Size int64 `json:"size,omitempty"`

	// Digest uniquely identifies the content. A byte stream can be verified
	// against against this digest.
	Digest digest.Digest `json:"digest,omitempty"`

	// URLs contains the source URLs of this content.
	URLs []string `json:"urls,omitempty"`
}

type Manifest struct {
	Config Descriptor   `json:"config"`
	Layers []Descriptor `json:"layers"`
}

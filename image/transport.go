package image

import (
	"net/http"
	"sync"
)

type RequestModifier interface {
	ModifyRequest(r *http.Request) error
}

type transport struct {
	Modifiers []RequestModifier
	mu        sync.Mutex
}

func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}

	return r2
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := cloneRequest(req)
	for _, modifier := range t.Modifiers {
		if err := modifier.ModifyRequest(req2); err != nil {
			return nil, err
		}
	}
	return http.DefaultTransport.RoundTrip(req2)
}

func NewTransport(modifiers ...RequestModifier) http.RoundTripper {
	return &transport{
		Modifiers: modifiers,
	}
}

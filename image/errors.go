package image

import (
	"fmt"
	"net/http"
)

type UnexpectedHTTPStatusError struct {
	Status string
}

func (e *UnexpectedHTTPStatusError) Error() string {
	return fmt.Sprintf("received unexpected HTTP status: %s", e.Status)
}

func HandleErrorResponse(resp *http.Response) error {
	return &UnexpectedHTTPStatusError{Status: resp.Status}
}

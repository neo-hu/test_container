// http 下载器

package image

import (
	"fmt"
	"github.com/pkg/errors"
	"io"
	"net/http"
	"os"
)

var (
	ErrWrongCodeForByteRange = errors.New("expected HTTP 206 from byte range request")
)

type ReadSeekCloser interface {
	io.ReadSeeker
	io.Closer
}

type httpReadSeeker struct {
	client       *http.Client
	url          string
	errorHandler func(*http.Response) error
	seekOffset   int64
	size         int64

	err          error
	readerOffset int64

	rc io.ReadCloser
}

func NewHTTPReadSeeker(client *http.Client, url string, errorHandler func(*http.Response) error) ReadSeekCloser {
	return &httpReadSeeker{
		client:       client,
		url:          url,
		errorHandler: errorHandler,
	}
}

func (hrs *httpReadSeeker) reset() {
	if hrs.err != nil {
		return
	}
	if hrs.rc != nil {
		hrs.rc.Close()
		hrs.rc = nil
	}
}

func (hrs *httpReadSeeker) Seek(offset int64, whence int) (int64, error) {
	if hrs.err != nil {
		return 0, hrs.err
	}

	lastReaderOffset := hrs.readerOffset

	if whence == os.SEEK_SET && hrs.rc == nil {
		// If no request has been made yet, and we are seeking to an
		// absolute position, set the read offset as well to avoid an
		// unnecessary request.
		hrs.readerOffset = offset
	}

	_, err := hrs.reader()
	if err != nil {
		hrs.readerOffset = lastReaderOffset
		return 0, err
	}

	newOffset := hrs.seekOffset

	switch whence {
	case os.SEEK_CUR:
		newOffset += offset
	case os.SEEK_END:
		if hrs.size < 0 {
			return 0, errors.New("content length not known")
		}
		newOffset = hrs.size + offset
	case os.SEEK_SET:
		newOffset = offset
	}

	if newOffset < 0 {
		err = errors.New("cannot seek to negative position")
	} else {
		hrs.seekOffset = newOffset
	}

	return hrs.seekOffset, err
}

func (hrs *httpReadSeeker) Close() error {
	if hrs.err != nil {
		return hrs.err
	}

	// close and release reader chain
	if hrs.rc != nil {
		hrs.rc.Close()
	}

	hrs.rc = nil

	hrs.err = errors.New("httpLayer: closed")

	return nil
}

func (hrs *httpReadSeeker) Read(p []byte) (n int, err error) {
	if hrs.err != nil {
		return 0, hrs.err
	}
	if hrs.readerOffset != hrs.seekOffset {
		hrs.reset()
	}

	hrs.readerOffset = hrs.seekOffset

	rd, err := hrs.reader()
	if err != nil {
		return 0, err
	}

	n, err = rd.Read(p)
	hrs.seekOffset += int64(n)
	hrs.readerOffset += int64(n)

	return n, err
}

func (hrs *httpReadSeeker) reader() (io.Reader, error) {

	if hrs.err != nil {
		return nil, hrs.err
	}

	if hrs.rc != nil {
		return hrs.rc, nil
	}

	req, err := http.NewRequest("GET", hrs.url, nil)
	if err != nil {
		return nil, err
	}

	if hrs.readerOffset > 0 {
		// If we are at different offset, issue a range request from there.
		req.Header.Add("Range", fmt.Sprintf("bytes=%d-", hrs.readerOffset))
		// TODO: get context in here
		// context.GetLogger(hrs.context).Infof("Range: %s", req.Header.Get("Range"))
	}

	req.Header.Add("Accept-Encoding", "identity")
	resp, err := hrs.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 399 {
		if hrs.readerOffset > 0 {
			if resp.StatusCode != http.StatusPartialContent {
				return nil, ErrWrongCodeForByteRange
			}
			panic("err")
		} else if resp.StatusCode == http.StatusOK {
			hrs.size = resp.ContentLength
		} else {
			hrs.size = -1
		}
		hrs.rc = resp.Body
	} else {
		defer resp.Body.Close()
		if hrs.errorHandler != nil {
			return nil, hrs.errorHandler(resp)
		}
		return nil, HandleErrorResponse(resp)
	}
	return hrs.rc, nil
}

package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func GenerateID(l int) string {
	const (
		// ensures we backoff for less than 450ms total. Use the following to
		// select new value, in units of 10ms:
		// 	n*(n+1)/2 = d -> n^2 + n - 2d -> n = (sqrt(8d + 1) - 1)/2
		maxretries = 9
		backoff    = time.Millisecond * 10
	)

	var (
		totalBackoff time.Duration
		count        int
		retries      int
		size         = (l*5 + 7) / 8
		u            = make([]byte, size)
	)
	// TODO: Include time component, counter component, random component

	for {
		// This should never block but the read may fail. Because of this,
		// we just try to read the random number generator until we get
		// something. This is a very rare condition but may happen.
		b := time.Duration(retries) * backoff
		time.Sleep(b)
		totalBackoff += b

		n, err := io.ReadFull(rand.Reader, u[count:])
		if err != nil {
			if retryOnError(err) && retries < maxretries {
				count += n
				retries++
				logrus.Errorf("error generating version 4 uuid, retrying: %v", err)
				continue
			}

			// Any other errors represent a system problem. What did someone
			// do to /dev/urandom?
			panic(fmt.Errorf("error reading random number generator, retried for %v: %v", totalBackoff.String(), err))
		}

		break
	}

	s := base32.StdEncoding.EncodeToString(u)

	return s[:l]
}
func retryOnError(err error) bool {
	switch err := err.(type) {
	case *os.PathError:
		return retryOnError(err.Err) // unpack the target error
	case syscall.Errno:
		if err == unix.EPERM {
			// EPERM represents an entropy pool exhaustion, a condition under
			// which we backoff and retry.
			return true
		}
	}

	return false
}

const shortLen = 12

func TruncateID(id string) string {
	if i := strings.IndexRune(id, ':'); i >= 0 {
		id = id[i+1:]
	}
	if len(id) > shortLen {
		id = id[:shortLen]
	}
	return id
}

type readerFunc func(p []byte) (int, error)

func (fn readerFunc) Read(p []byte) (int, error) {
	return fn(p)
}

func generateID(r io.Reader) string {
	b := make([]byte, 32)
	for {
		if _, err := io.ReadFull(r, b); err != nil {
			panic(err) // This shouldn't happen
		}
		id := hex.EncodeToString(b)
		// if we try to parse the truncated for as an int and we don't have
		// an error then the value is all numeric and causes issues when
		// used as a hostname. ref #3869
		if _, err := strconv.ParseInt(TruncateID(id), 10, 64); err == nil {
			continue
		}
		return id
	}
}

func GenerateNonCryptoID() string {
	return generateID(readerFunc(rand.Read))
}

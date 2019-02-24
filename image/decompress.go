package image

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const buffer32K = 32 * 1024

var (
	BufioReader32KPool = newBufioReaderPoolWithSize(buffer32K)
)

func newBufioReaderPoolWithSize(size int) *BufioReaderPool {
	return &BufioReaderPool{
		pool: sync.Pool{
			New: func() interface{} { return bufio.NewReaderSize(nil, size) },
		},
	}
}

type BufioReaderPool struct {
	pool sync.Pool
}

func (bufPool *BufioReaderPool) Get(r io.Reader) *bufio.Reader {
	buf := bufPool.pool.Get().(*bufio.Reader)
	buf.Reset(r)
	return buf
}

func DecompressStream(archive io.Reader) (io.Reader, error) {
	buf := bufio.NewReaderSize(archive, buffer32K)
	bs, err := buf.Peek(10)
	if err != nil && err != io.EOF {
		// Note: we'll ignore any io.EOF error because there are some odd
		// cases where the layer.tar file will be empty (zero bytes) and
		// that results in an io.EOF from the Peek() call. So, in those
		// cases we'll just treat it as a non-compressed stream and
		// that means just create an empty layer.
		// See Issue 18170
		return nil, err
	}
	compression := DetectCompression(bs)
	switch compression {
	case Uncompressed:
		return archive, nil
	case Gzip:
		return gzip.NewReader(buf)
	default:
		return nil, fmt.Errorf("Unsupported compression format %s", (&compression).Extension())
	}
}

type (
	Compression int
)

func (compression *Compression) Extension() string {
	switch *compression {
	case Uncompressed:
		return "tar"
	case Bzip2:
		return "tar.bz2"
	case Gzip:
		return "tar.gz"
	case Xz:
		return "tar.xz"
	}
	return ""
}

const (
	// Uncompressed represents the uncompressed.
	Uncompressed Compression = iota
	// Bzip2 is bzip2 compression algorithm.
	Bzip2
	// Gzip is gzip compression algorithm.
	Gzip
	// Xz is xz compression algorithm.
	Xz
)

func DetectCompression(source []byte) Compression {
	for compression, m := range map[Compression][]byte{
		Bzip2: {0x42, 0x5A, 0x68},
		Gzip:  {0x1F, 0x8B, 0x08},
		Xz:    {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00},
	} {
		if len(source) < len(m) {
			logrus.Debug("Len too short")
			continue
		}
		if bytes.Equal(m, source[:len(m)]) {
			return compression
		}
	}
	return Uncompressed
}

func applyTar(r io.Reader, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		err = os.RemoveAll(dest)
		if err != nil {
			return err
		}
	}
	return unpack(r, dest)
}

func unpack(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	var dirs []*tar.Header
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			// end of tar archive
			break
		}
		if err != nil {
			return err
		}
		hdr.Name = filepath.Clean(hdr.Name)
		if !strings.HasSuffix(hdr.Name, string(os.PathSeparator)) {
			parent := filepath.Dir(hdr.Name)
			parentPath := filepath.Join(dest, parent)
			if _, err := os.Lstat(parentPath); err != nil && os.IsNotExist(err) {
				err = MkdirAll(parentPath, 0755)
				if err != nil {
					return err
				}
			}
		}
		path := filepath.Join(dest, hdr.Name)
		rel, err := filepath.Rel(dest, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("%q is outside of %q", hdr.Name, dest)
		}
		if fi, err := os.Lstat(path); err == nil {
			if fi.IsDir() && hdr.Name == "." {
				continue
			}

			if !(fi.IsDir() && hdr.Typeflag == tar.TypeDir) {
				if err := os.RemoveAll(path); err != nil {
					return err
				}
			}
		}
		if err := createTarFile(path, dest, hdr, tr); err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeDir {
			dirs = append(dirs, hdr)
		}
	}
	for _, hdr := range dirs {
		path := filepath.Join(dest, hdr.Name)
		if err := Chtimes(path, hdr.AccessTime, hdr.ModTime); err != nil {
			return err
		}
	}
	return nil
}

func createTarFile(path, extractDir string, hdr *tar.Header, reader io.Reader) error {
	hdrInfo := hdr.FileInfo()
	switch hdr.Typeflag {
	case tar.TypeDir:
		if fi, err := os.Lstat(path); !(err == nil && fi.IsDir()) {
			if err := os.Mkdir(path, hdrInfo.Mode()); err != nil {
				return err
			}
		}
	case tar.TypeReg, tar.TypeRegA:
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, hdrInfo.Mode())
		if err != nil {
			return err
		}
		if _, err := io.Copy(file, reader); err != nil {
			file.Close()
			return err
		}
		file.Close()
	case tar.TypeLink:
		targetPath := filepath.Join(extractDir, hdr.Linkname)
		// check for hardlink breakout
		if !strings.HasPrefix(targetPath, extractDir) {
			return fmt.Errorf("invalid hardlink %q -> %q", targetPath, hdr.Linkname)
		}
		if err := os.Link(targetPath, path); err != nil {
			return err
		}
	case tar.TypeBlock, tar.TypeChar:
		// Handle this is an OS-specific way
		if err := handleTarTypeBlockCharFifo(hdr, path); err != nil {
			return err
		}
	case tar.TypeSymlink:
		targetPath := filepath.Join(filepath.Dir(path), hdr.Linkname)
		if !strings.HasPrefix(targetPath, extractDir) {
			return fmt.Errorf("invalid symlink %q -> %q", path, hdr.Linkname)
		}
		if err := os.Symlink(hdr.Linkname, path); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unhandled tar header type %s", string(hdr.Typeflag))
	}

	var errors []string
	for key, value := range hdr.Xattrs {
		if err := unix.Lsetxattr(path, key, []byte(value), 0); err != nil {
			if err == syscall.ENOTSUP {
				// We ignore errors here because not all graphdrivers support
				// xattrs *cough* old versions of AUFS *cough*. However only
				// ENOTSUP should be emitted in that case, otherwise we still
				// bail.
				errors = append(errors, err.Error())
				continue
			}
			return err
		}

	}
	if len(errors) > 0 {
		logrus.WithFields(logrus.Fields{
			"errors": errors,
		}).Warn("ignored xattrs in archive: underlying filesystem doesn't support them")
	}

	if hdr.Typeflag == tar.TypeLink {
		if fi, err := os.Lstat(hdr.Linkname); err == nil && (fi.Mode()&os.ModeSymlink == 0) {
			if err := os.Chmod(path, hdrInfo.Mode()); err != nil {
				return err
			}
		}
	} else if hdr.Typeflag != tar.TypeSymlink {
		if err := os.Chmod(path, hdrInfo.Mode()); err != nil {
			return err
		}
	}

	aTime := hdr.AccessTime
	if aTime.Before(hdr.ModTime) {
		// Last access time should never be before last modified time.
		aTime = hdr.ModTime
	}
	if hdr.Typeflag == tar.TypeLink {
		if fi, err := os.Lstat(hdr.Linkname); err == nil && (fi.Mode()&os.ModeSymlink == 0) {
			if err := Chtimes(path, aTime, hdr.ModTime); err != nil {
				return err
			}
		}
	} else if hdr.Typeflag != tar.TypeSymlink {
		if err := Chtimes(path, aTime, hdr.ModTime); err != nil {
			return err
		}
	} else {
		ts := []syscall.Timespec{timeToTimespec(aTime), timeToTimespec(hdr.ModTime)}
		if err := LUtimesNano(path, ts); err != nil {
			return err
		}
	}
	return nil
}

func timeToTimespec(time time.Time) (ts syscall.Timespec) {
	if time.IsZero() {
		// Return UTIME_OMIT special value
		ts.Sec = 0
		ts.Nsec = (1 << 30) - 2
		return
	}
	return syscall.NsecToTimespec(time.UnixNano())
}

func LUtimesNano(path string, ts []syscall.Timespec) error {
	atFdCwd := unix.AT_FDCWD

	var _path *byte
	_path, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	if _, _, err := unix.Syscall6(unix.SYS_UTIMENSAT, uintptr(atFdCwd), uintptr(unsafe.Pointer(_path)), uintptr(unsafe.Pointer(&ts[0])), unix.AT_SYMLINK_NOFOLLOW, 0, 0); err != 0 && err != unix.ENOSYS {
		return err
	}

	return nil
}

func handleTarTypeBlockCharFifo(hdr *tar.Header, path string) error {
	mode := uint32(hdr.Mode & 07777)
	switch hdr.Typeflag {
	case tar.TypeBlock:
		mode |= unix.S_IFBLK
	case tar.TypeChar:
		mode |= unix.S_IFCHR
	case tar.TypeFifo:
		mode |= unix.S_IFIFO
	}

	return unix.Mknod(path, mode, int(unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor))))
}

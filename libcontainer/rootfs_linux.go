package libcontainer

import (
	"fmt"
	"github.com/cyphar/filepath-securejoin"
	"github.com/mrunalp/fileutils"
	"github.com/neo-hu/test_container/config"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// EXT_COPYUP is a directive to copy up the contents of a directory when
	// a tmpfs is mounted over it.
	EXT_COPYUP = 1 << iota
)

func PrepareRootfs(initConfig *config.InitCofing) error {
	err := prepareRoot(initConfig)
	if err != nil {
		return err
	}

	for _, m := range initConfig.Mounts {
		if err := mountToRootfs(m, initConfig.Rootfs, initConfig.Spec.Linux.MountLabel); err != nil {
			return errors.Wrapf(err, "mounting %q to rootfs %q at %q", m.Source, initConfig.Rootfs, m.Destination)
		}
	}

	if err := unix.Chdir(initConfig.Rootfs); err != nil {
		return errors.Wrapf(err, "changing dir to %q", initConfig.Rootfs)
	}
	// 设定根目录
	if initConfig.Spec.Linux.Namespaces.Contains(config.MountNamespace) {
		err = pivotRoot(initConfig.Rootfs)
	} else {
		err = chroot(initConfig.Rootfs)
	}
	if err != nil {
		return errors.Wrapf(err, "jailing process inside rootfs")
	}
	if cwd := initConfig.Spec.Process.Cwd; cwd != "" {
		// Note that spec.Process.Cwd can contain unclean value like  "../../../../foo/bar...".
		// However, we are safe to call MkDirAll directly because we are in the jail here.
		if err := os.MkdirAll(cwd, 0755); err != nil {
			return err
		}
	}
	if initConfig.Spec.Linux.Namespaces.Contains(config.MountNamespace) {
		if err := finalizeRootfs(initConfig); err != nil {
			return err
		}
	}
	return nil
}

func MaskPath(path string, mountLabel string) error {
	if err := unix.Mount("/dev/null", path, "", unix.MS_BIND, ""); err != nil && !os.IsNotExist(err) {
		if err == unix.ENOTDIR {
			return unix.Mount("tmpfs", path, "tmpfs", unix.MS_RDONLY, mountLabel)
		}
		return err
	}
	return nil
}

func ReadonlyPath(path string) error {
	if err := unix.Mount(path, path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return unix.Mount(path, path, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, "")
}

func chroot(rootfs string) error {
	if err := unix.Chroot("."); err != nil {
		return err
	}
	return unix.Chdir("/")
}

func pivotRoot(rootfs string) error {
	oldroot, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(oldroot)
	newroot, err := unix.Open(rootfs, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(newroot)
	if err := unix.Fchdir(newroot); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root %s", err)
	}
	if err := unix.Fchdir(oldroot); err != nil {
		return err
	}
	if err := unix.Mount("", ".", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return err
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return err
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir / %s", err)
	}

	return nil
}

func mountToRootfs(m *config.LibMount, rootfs, mountLabel string) error {
	var (
		dest = m.Destination
	)
	if !strings.HasPrefix(dest, rootfs) {
		dest = filepath.Join(rootfs, dest)
	}
	switch m.Device {
	case "proc", "sysfs":
		if err := os.MkdirAll(dest, 0755); err != nil {
			return err
		}
		// Selinux kernels do not support labeling of /proc or /sys
		return mountPropagate(m, rootfs, "")
	case "mqueue":
		if err := os.MkdirAll(dest, 0755); err != nil {
			return err
		}
		if err := mountPropagate(m, rootfs, mountLabel); err != nil {
			// older kernels do not support labeling of /dev/mqueue
			if err := mountPropagate(m, rootfs, ""); err != nil {
				return err
			}
			return nil
		}
		return nil
	case "tmpfs":
		copyUp := m.Extensions&config.EXT_COPYUP == config.EXT_COPYUP
		tmpDir := ""
		stat, err := os.Stat(dest)
		if err != nil {
			if err := os.MkdirAll(dest, 0755); err != nil {
				return err
			}
		}
		if copyUp {
			tmpDir, err = ioutil.TempDir("/tmp", "runctmpdir")
			if err != nil {
				return err
			}
			defer os.RemoveAll(tmpDir)
			m.Destination = tmpDir
		}
		if err := mountPropagate(m, rootfs, mountLabel); err != nil {
			return err
		}
		if copyUp {
			if err := fileutils.CopyDirectory(dest, tmpDir); err != nil {
				return err
			}

			if err := unix.Mount(tmpDir, dest, "", unix.MS_MOVE, ""); err != nil {
				return err
			}

		}
		if stat != nil {
			if err = os.Chmod(dest, stat.Mode()); err != nil {
				return err
			}
		}
		return nil
	case "bind":
		// resolv.conf hosts ....
		stat, err := os.Stat(m.Source)
		if err != nil {
			// error out if the source of a bind mount does not exist as we will be
			// unable to bind anything to it.
			return err
		}
		if dest, err = securejoin.SecureJoin(rootfs, m.Destination); err != nil {
			return err
		}
		if err := checkMountDestination(rootfs, dest); err != nil {
			return err
		}
		m.Destination = dest
		if err := createIfNotExists(dest, stat.IsDir()); err != nil {
			return err
		}
		if err := mountPropagate(m, rootfs, mountLabel); err != nil {
			return err
		}

		// bind mount won't change mount options, we need remount to make mount options effective.
		// first check that we have non-default options required before attempting a remount
		if m.Flags&^(unix.MS_REC|unix.MS_REMOUNT|unix.MS_BIND) != 0 {
			// only remount if unique mount options are set
			if err := remount(m, rootfs); err != nil {
				return err
			}
		}
	case "cgroup":
		fmt.Println(m.Source, dest)
		return nil
	default:
		var err error
		if dest, err = securejoin.SecureJoin(rootfs, m.Destination); err != nil {
			return err
		}
		if err := checkMountDestination(rootfs, dest); err != nil {
			return err
		}
		m.Destination = dest
		if err := os.MkdirAll(dest, 0755); err != nil {
			return err
		}
		return mountPropagate(m, rootfs, "")
	}
	return nil
}

func finalizeRootfs(initConfig *config.InitCofing) error {
	for _, m := range initConfig.Mounts {
		if config.CleanPath(m.Destination) == "/dev" {
			if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {
				if err := remountReadonly(m); err != nil {
					return errors.Wrapf(err, "remounting %q as readonly", m.Destination)
				}
			}
			break
		}
	}
	if initConfig.Spec.Root.Readonly {
		if err := setReadonly(); err != nil {
			return errors.Wrap(err, "setting rootfs as readonly")
		}
	}
	unix.Umask(0022)
	return nil
}

func setReadonly() error {
	return unix.Mount("/", "/", "bind", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, "")
}
func remountReadonly(m *config.LibMount) error {
	var (
		dest  = m.Destination
		flags = m.Flags
	)
	for i := 0; i < 5; i++ {
		// There is a special case in the kernel for
		// MS_REMOUNT | MS_BIND, which allows us to change only the
		// flags even as an unprivileged user (i.e. user namespace)
		// assuming we don't drop any security related flags (nodev,
		// nosuid, etc.). So, let's use that case so that we can do
		// this re-mount without failing in a userns.
		flags |= unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY
		if err := unix.Mount("", dest, "", uintptr(flags), ""); err != nil {
			switch err {
			case unix.EBUSY:
				time.Sleep(100 * time.Millisecond)
				continue
			default:
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unable to mount %s as readonly max retries reached", dest)
}

func remount(m *config.LibMount, rootfs string) error {
	var (
		dest = m.Destination
	)
	if !strings.HasPrefix(dest, rootfs) {
		dest = filepath.Join(rootfs, dest)
	}
	if err := unix.Mount(m.Source, dest, m.Device, uintptr(m.Flags|unix.MS_REMOUNT), ""); err != nil {
		return err
	}
	return nil
}

func createIfNotExists(path string, isDir bool) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			if isDir {
				return os.MkdirAll(path, 0755)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_CREATE, 0755)
			if err != nil {
				return err
			}
			f.Close()
		}
	}
	return nil
}

func checkMountDestination(rootfs, dest string) error {
	invalidDestinations := []string{
		"/proc",
	}
	validDestinations := []string{
		// These entries can be bind mounted by files emulated by fuse,
		// so commands like top, free displays stats in container.
		"/proc/cpuinfo",
		"/proc/diskstats",
		"/proc/meminfo",
		"/proc/stat",
		"/proc/swaps",
		"/proc/uptime",
		"/proc/net/dev",
	}

	for _, valid := range validDestinations {
		path, err := filepath.Rel(filepath.Join(rootfs, valid), dest)
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}
	}
	for _, invalid := range invalidDestinations {
		path, err := filepath.Rel(filepath.Join(rootfs, invalid), dest)
		if err != nil {
			return err
		}
		if path == "." || !strings.HasPrefix(path, "..") {
			return fmt.Errorf("%q cannot be mounted because it is located inside %q", dest, invalid)
		}
	}
	return nil
}

func mountPropagate(m *config.LibMount, rootfs string, mountLabel string) error {
	var (
		dest  = m.Destination
		data  = mountLabel
		flags = m.Flags
	)
	if config.CleanPath(dest) == "/dev" {
		flags &= ^unix.MS_RDONLY
	}
	copyUp := m.Extensions&config.EXT_COPYUP == config.EXT_COPYUP
	if !(copyUp || strings.HasPrefix(dest, rootfs)) {
		dest = filepath.Join(rootfs, dest)
	}

	if err := unix.Mount(m.Source, dest, m.Device, uintptr(flags), data); err != nil {
		return err
	}
	for _, pflag := range m.PropagationFlags {
		if err := unix.Mount("", dest, "", uintptr(pflag), ""); err != nil {
			return err
		}
	}
	return nil
}

var mountPropagationMapping = map[string]int{
	"rprivate":    unix.MS_PRIVATE | unix.MS_REC,
	"private":     unix.MS_PRIVATE,
	"rslave":      unix.MS_SLAVE | unix.MS_REC,
	"slave":       unix.MS_SLAVE,
	"rshared":     unix.MS_SHARED | unix.MS_REC,
	"shared":      unix.MS_SHARED,
	"runbindable": unix.MS_UNBINDABLE | unix.MS_REC,
	"unbindable":  unix.MS_UNBINDABLE,
	"":            0,
}

func prepareRoot(initConfig *config.InitCofing) error {
	flag := unix.MS_SLAVE | unix.MS_REC
	if rootPropagation, exists := mountPropagationMapping[initConfig.Spec.Linux.RootfsPropagation]; exists {
		if rootPropagation != 0 {
			flag = rootPropagation
		}
	}
	if err := unix.Mount("", "/", "", uintptr(flag), ""); err != nil {
		return err
	}
	return unix.Mount(initConfig.Rootfs, initConfig.Rootfs, "bind", unix.MS_BIND|unix.MS_REC, "")
}

package main

import (
	"encoding/json"
	"fmt"
	"github.com/neo-hu/test_container/config"
	"github.com/neo-hu/test_container/libcontainer"
	_ "github.com/neo-hu/test_container/nsenter"
	"github.com/neo-hu/test_container/seccomp"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
	}
}

var initCommand = cli.Command{
	Name: "init",
	Action: func(context *cli.Context) error {
		err := StartInitialization()
		if err != nil {
			return err
		}
		return nil
	},
}

func StartInitialization() error {
	var (
		parentPid   = unix.Getppid()
		envInitPipe = os.Getenv("_LIBCONTAINER_INITPIPE")
	)
	pipefd, err := strconv.Atoi(envInitPipe)
	if err != nil {
		return fmt.Errorf("unable to convert _LIBCONTAINER_INITPIPE=%s to int: %s", envInitPipe, err)
	}
	pipe := os.NewFile(uintptr(pipefd), "pipe")
	defer pipe.Close()
	var initConfig *config.InitCofing
	if err := json.NewDecoder(pipe).Decode(&initConfig); err != nil {
		return err
	}
	err = populateProcessEnvironment(initConfig.Spec.Process.Env)
	if err != nil {
		return err
	}
	// todo 设定文件系统根目录
	err = libcontainer.PrepareRootfs(initConfig)
	if err != nil {
		return err
	}

	// todo 设置hostname
	if initConfig.Spec.Linux.Namespaces.Contains(config.UTSNamespace) {
		if hostname := initConfig.Spec.Hostname; hostname != "" {
			if err := unix.Sethostname([]byte(hostname)); err != nil {
				return errors.Wrap(err, "sethostname")
			}
		}
	}

	//initConfig.Spec.Process.ApparmorProfile  not supported
	for key, value := range initConfig.Spec.Linux.Sysctl {
		if err := writeSystemProperty(key, value); err != nil {
			return errors.Wrapf(err, "write sysctl key %s", key)
		}
	}

	// todo 处理只读路径
	for _, path := range initConfig.Spec.Linux.ReadonlyPaths {
		if err := libcontainer.ReadonlyPath(path); err != nil {
			return errors.Wrapf(err, "readonly path %s", path)
		}
	}

	for _, path := range initConfig.Spec.Linux.MaskedPaths {
		if err := libcontainer.MaskPath(path, initConfig.Spec.Linux.MountLabel); err != nil {
			return errors.Wrapf(err, "mask path %s", path)
		}
	}
	if initConfig.Spec.Process.NoNewPrivileges {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return errors.Wrap(err, "set nonewprivileges")
		}
	}

	if initConfig.Spec.Linux.Seccomp != nil && !initConfig.Spec.Process.NoNewPrivileges {
		// todo 设置容器的权限
		if err := seccomp.InitSeccomp(initConfig.Spec.Linux.Seccomp); err != nil {
			return err
		}
	}

	if unix.Getppid() != parentPid {
		return unix.Kill(unix.Getpid(), unix.SIGKILL)
	}
	name, err := exec.LookPath(initConfig.Spec.Process.Args[0])
	if err != nil {
		return err
	}
	pipe.Close()

	if err := syscall.Exec(name, initConfig.Spec.Process.Args[0:], os.Environ()); err != nil {
		return errors.Wrap(err, "exec user process")
	}
	return nil
}

func writeSystemProperty(key, value string) error {
	keyPath := strings.Replace(key, ".", "/", -1)
	return ioutil.WriteFile(path.Join("/proc/sys", keyPath), []byte(value), 0644)
}

/* 设置环境变量*/
func populateProcessEnvironment(env []string) error {
	for _, pair := range env {
		p := strings.SplitN(pair, "=", 2)
		if len(p) < 2 {
			return fmt.Errorf("invalid environment '%v'", pair)
		}
		if err := os.Setenv(p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
}

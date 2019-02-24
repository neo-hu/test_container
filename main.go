package main

import (
	"bytes"
	gocontext "context"
	"encoding/json"
	"fmt"
	"github.com/neo-hu/test_container/config"
	image2 "github.com/neo-hu/test_container/image"
	"github.com/neo-hu/test_container/oci"
	"github.com/neo-hu/test_container/seccomp"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"syscall"
)

type Record struct {
	Hosts string
	IP    string
}

// WriteTo writes record to file and returns bytes written or error
func (r Record) WriteTo(w io.Writer) (int64, error) {
	n, err := fmt.Fprintf(w, "%s\t%s\n", r.IP, r.Hosts)
	return int64(n), err
}

func NewSockPair(name string) (parent *os.File, child *os.File, err error) {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), name+"-p"), os.NewFile(uintptr(fds[0]), name+"-c"), nil
}

const (
	driverName = "overlay2"
	RootDir    = "/tmp/docker"
)

var (
	linkDir        = path.Join(RootDir, driverName, "l")
	defaultContent = []Record{
		{Hosts: "localhost", IP: "127.0.0.1"},
		{Hosts: "localhost ip6-localhost ip6-loopback", IP: "::1"},
		{Hosts: "ip6-localnet", IP: "fe00::0"},
		{Hosts: "ip6-mcastprefix", IP: "ff00::0"},
		{Hosts: "ip6-allnodes", IP: "ff02::1"},
		{Hosts: "ip6-allrouters", IP: "ff02::2"},
	}
)

func main() {
	app := cli.NewApp()
	logrus.SetLevel(logrus.DebugLevel)
	app.Action = func(context *cli.Context) error {
		clean()
		ctx, cancel := gocontext.WithCancel(gocontext.Background())
		Trap(func(s string) {
			fmt.Println(s)
			cancel()
		})
		args := context.Args()
		image := args[0]
		// todo step 1 下载镜像
		imageConfig, layer, err := image2.PullImage(ctx, path.Join(RootDir, driverName), image)
		if err != nil {
			return err
		}
		// todo 生成容器id
		containerId := fmt.Sprintf("container-%s", GenerateID(23))
		logrus.Infof("container id %s", containerId)

		// todo step 2 使用下载镜像构建容器的根目录
		root, err := initMount(containerId, layer)
		if err != nil {
			return err
		}
		spec := oci.DefaultLinuxSpec()
		spec.Process.Env = imageConfig.Config.Env
		spec.Process.Env = append(spec.Process.Env, "TERM=xterm-256color")
		spec.Process.Args = imageConfig.Config.Cmd
		spec.Process.Cwd = imageConfig.Config.WorkingDir
		spec.Root.Path = root
		if spec.Process.Cwd == "" {
			spec.Process.Cwd = "/"
		}
		if len(args) > 1 {
			spec.Process.Args = args[1:]
		}
		spec.Hostname = GenerateNonCryptoID()[:12]
		source, err := buildHostnameFile(containerId, spec.Hostname)
		if err != nil {
			return err
		}
		spec.Mounts = append(spec.Mounts, config.Mount{
			Source:      source,
			Destination: "/etc/hostname",
			Type:        "bind",
			Options: []string{
				"rbind", "rprivate",
			},
		})

		if ok := spec.Mounts.Contains("/etc/hosts"); !ok {
			source, err := buildHostsFile(containerId)
			if err != nil {
				return err
			}
			spec.Mounts = append(spec.Mounts, config.Mount{
				Source:      source,
				Destination: "/etc/hosts",
				Type:        "bind",
				Options: []string{
					"rbind", "rprivate",
				},
			})
		}
		spec.Linux.Seccomp = seccomp.DefaultProfile(&spec)
		parentPipe, childPipe, err := NewSockPair("init")
		if err != nil {
			return errors.Wrap(err, "creating new init pipe")
		}
		//
		initConfig, err := config.CreateInitCofing(&spec)
		if err != nil {
			return err
		}
		// todo step 3 fock一个 init.go 进程并且设定namespaces
		cmd := cmdTemp(initConfig, childPipe)

		return start(cmd, bootstrapData(&spec), parentPipe, childPipe, initConfig, ctx)
	}
	app.Commands = []cli.Command{
		initCommand,
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}

func Trap(cleanup func(string)) {
	c := make(chan os.Signal, 1)
	signals := []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE}
	signal.Notify(c, signals...)
	go func() {
		for sig := range c {
			if sig == syscall.SIGPIPE {
				continue
			}
			go func(sig os.Signal) {
				switch sig {
				case os.Interrupt, syscall.SIGTERM:
					cleanup(fmt.Sprintf("with signal '%v'", sig))
				}
			}(sig)
		}
	}()
}

func buildHostsFile(containerId string) (string, error) {
	dir := path.Join(RootDir, driverName, containerId, "hosts")
	f, err := os.OpenFile(dir, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}
	for _, r := range defaultContent {
		_, err := r.WriteTo(f)
		if err != nil {
			return "", err
		}
	}
	return dir, nil
}
func buildHostnameFile(containerId, hostname string) (string, error) {
	dir := path.Join(RootDir, driverName, containerId, "hostname")
	return dir, ioutil.WriteFile(dir, []byte(hostname+"\n"), 0644)
}

// 清理垃圾数据
func clean() error {
	root := path.Join(RootDir, driverName)
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	f, err := os.Open(root)
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(-1)
	for _, n := range names {
		// 下载的临时文件
		if strings.HasPrefix(n, "GetImageBlob") {
			os.RemoveAll(path.Join(root, n))
		}
		// 容器运行环境
		if strings.HasPrefix(n, "container") {
			// mount
			mergedDir := path.Join(root, n, "merged")
			unix.Unmount(mergedDir, unix.MNT_DETACH)
			os.RemoveAll(path.Join(root, n))
		}
	}
	return nil
}

func initMount(containerId string, layer *image2.Layer) (string, error) {
	_, err := os.Stat(linkDir)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(linkDir, 0755); err != nil {
				return "", errors.Wrapf(err, "mkdir %s err", linkDir)
			}
		} else {
			return "", err
		}
	}

	dir := path.Join(RootDir, driverName, containerId)
	if _, err := os.Stat(dir); err == nil || !os.IsNotExist(err) {
		return "", errors.Wrapf(err, "stat container dir %s err", dir)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	for _, d := range []string{"diff", "work", "merged"} {
		if err := os.Mkdir(path.Join(dir, d), 0755); err != nil {
			return "", err
		}
	}

	var absLowers []string
	for layer != nil {
		diffDir := path.Join(layer.Dir(), "diff")
		if _, err := os.Stat(diffDir); err != nil {
			return "", errors.Wrapf(err, dir)
		}
		linkFile := path.Join(layer.Dir(), "link")
		linkData, err := ioutil.ReadFile(linkFile)
		if err != nil {
			if os.IsNotExist(err) {
				// todo link 不存在，建立短的软连接, 缩短 mount data的大小
				lid := GenerateID(32)
				if err := os.Symlink(diffDir, path.Join(linkDir, lid)); err != nil {
					return "", err
				}
				linkData = []byte(lid)
				if err = ioutil.WriteFile(linkFile, linkData, 0644); err != nil {
					return "", err
				}
			} else {
				return "", err
			}
		} else {
			// todo 验证软连接是否存在
			_, err := os.Lstat(path.Join(linkDir, string(linkData)))
			if err != nil && os.IsNotExist(err) {
				if err := os.Symlink(diffDir, path.Join(linkDir, string(linkData))); err != nil {
					return "", err
				}
			}
		}
		absLowers = append(absLowers, path.Join(linkDir, string(linkData)))
		layer = layer.Parent()
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", strings.Join(absLowers, ":"), path.Join(dir, "diff"), path.Join(dir, "work"))

	pageSize := unix.Getpagesize()
	if pageSize > 4096 {
		pageSize = 4096
	}
	// todo 当镜像的layers太多，参数超过页内存的大小
	if len(opts) > pageSize {
		return "", fmt.Errorf("cannot mount layer, mount label too large %d", len(opts))
	}
	mergedDir := path.Join(dir, "merged")
	if err := unix.Mount("overlay", mergedDir, "overlay", 0, opts); err != nil {
		return "", errors.Wrapf(err, "mount opts:%s", opts)
	}
	return mergedDir, nil
}

func cmdTemp(cfg *config.InitCofing, childPipe *os.File) *exec.Cmd {
	cmd := exec.Command("/proc/self/exe", "init")
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Dir = cfg.Rootfs
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("GOMAXPROCS=%s", os.Getenv("GOMAXPROCS")))

	cmd.ExtraFiles = append(cmd.ExtraFiles, childPipe)
	// todo _LIBCONTAINER_INITPIPE=childPipe 环境变量用于进程间通信 to init.go:53
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("_LIBCONTAINER_INITPIPE=%d", 3+len(cmd.ExtraFiles)-1),
	)
	return cmd
}

type pid struct {
	Pid           int `json:"pid"`
	PidFirstChild int `json:"pid_first"`
}

func start(cmd *exec.Cmd, bootstrapData io.Reader, parentPipe *os.File, childPipe *os.File, initConfig *config.InitCofing, ctx gocontext.Context) error {
	defer parentPipe.Close()
	// todo 启动init进程
	err := cmd.Start()
	childPipe.Close()
	if err != nil {
		return err
	}
	// todo 发送namespaces数据到init进程 通过nsenter/nsexec.c 设置进程Namespaces
	if _, err := io.Copy(parentPipe, bootstrapData); err != nil {
		return err
	}
	status, err := cmd.Process.Wait()
	if err != nil {
		cmd.Wait()
		return err
	}
	if !status.Success() {
		cmd.Wait()
		return &exec.ExitError{ProcessState: status}
	}
	//todo nsenter/nsexec.c 设置成功后返回pid
	var pid *pid
	if err := json.NewDecoder(parentPipe).Decode(&pid); err != nil {
		cmd.Wait()
		return err
	}

	firstChildProcess, err := os.FindProcess(pid.PidFirstChild)
	if err != nil {
		return err
	}
	_, _ = firstChildProcess.Wait()
	p, err := os.FindProcess(pid.Pid)
	if err != nil {
		return err
	}
	fmt.Println(pid.Pid, "pid.Pid")
	// todo 发送容器配置数据
	err = sendConfig(parentPipe, initConfig)
	if err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		_, err := p.Wait()
		done <- err
	}()

	select {
	case <-ctx.Done():
		syscall.Kill(-pid.Pid, syscall.SIGKILL)
		err := <-done
		return err
	case err := <-done:
		return err
	}
}

func sendConfig(parentPipe *os.File, initConfig *config.InitCofing) error {
	data, err := json.Marshal(initConfig)
	if err != nil {
		return err
	}
	_, err = parentPipe.Write(data)
	return err
}

// 生成namespaces数据
func bootstrapData(spec *config.Spec) io.Reader {
	r := nl.NewNetlinkRequest(int(InitMsg), 0)
	cloneFlags := spec.Linux.Namespaces.CloneFlags()
	r.AddData(&Int32msg{
		Type:  CloneFlagsAttr,
		Value: uint32(cloneFlags),
	})
	if spec.Process.OOMScoreAdj != nil {
		r.AddData(&Bytemsg{
			Type:  OomScoreAdjAttr,
			Value: []byte(fmt.Sprintf("%d", *spec.Process.OOMScoreAdj)),
		})
	}
	r.AddData(&Boolmsg{
		Type:  RootlessAttr,
		Value: false,
	})
	return bytes.NewReader(r.Serialize())
}

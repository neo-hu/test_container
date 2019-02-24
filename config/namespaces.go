package config

import (
	"golang.org/x/sys/unix"
)

type Namespaces []LinuxNamespace

var namespaceInfo = map[LinuxNamespaceType]int{
	NetworkNamespace: unix.CLONE_NEWNET,
	MountNamespace:   unix.CLONE_NEWNS,
	UserNamespace:    unix.CLONE_NEWUSER,
	IPCNamespace:     unix.CLONE_NEWIPC,
	UTSNamespace:     unix.CLONE_NEWUTS,
	PIDNamespace:     unix.CLONE_NEWPID,
}

func (n *Namespaces) NsPathMap() map[LinuxNamespaceType]string {
	nsMaps := make(map[LinuxNamespaceType]string)
	for _, ns := range *n {
		if ns.Path != "" {
			nsMaps[ns.Type] = ns.Path
		}
	}
	return nsMaps
}
func (n *Namespaces) CloneFlags() uintptr {
	var flag int
	for _, v := range *n {
		if v.Path != "" {
			continue
		}
		if f, ok := namespaceInfo[v.Type]; ok {
			flag |= f
		}
	}
	return uintptr(flag)
}

func (n *Namespaces) Add(t LinuxNamespaceType, path string) {
	i := n.index(t)
	if i == -1 {
		*n = append(*n, LinuxNamespace{Type: t, Path: path})
		return
	}
	(*n)[i].Path = path
}

func (n *Namespaces) index(t LinuxNamespaceType) int {
	for i, ns := range *n {
		if ns.Type == t {
			return i
		}
	}
	return -1
}

func (n *Namespaces) Contains(t LinuxNamespaceType) bool {
	return n.index(t) != -1
}

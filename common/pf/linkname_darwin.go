package pf

import (
	"unsafe"
)

//go:linkname unixIoctlPtr golang.org/x/sys/unix.ioctlPtr
func unixIoctlPtr(fd int, request uint, arg unsafe.Pointer) error

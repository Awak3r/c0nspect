//go:build unix

package conspectclient

import (
	"os"
	"syscall"
)

func readOnlyFlags() int {
	// Nonblocking opens keep a concurrently substituted FIFO from hanging startup
	// or a file tool. Every opened descriptor is checked to be a regular file.
	return os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
}

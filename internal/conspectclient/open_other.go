//go:build !unix

package conspectclient

import "os"

func readOnlyFlags() int {
	return os.O_RDONLY
}

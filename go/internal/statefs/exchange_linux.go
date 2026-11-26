package statefs

import (
	"syscall"
	"unsafe"
)

const renameExchange = 1 << 1 // RENAME_EXCHANGE

// exchange atomically swaps two directory entries (renameat2 RENAME_EXCHANGE).
func exchange(a, b string) error {
	pa, err := syscall.BytePtrFromString(a)
	if err != nil {
		return err
	}
	pb, err := syscall.BytePtrFromString(b)
	if err != nil {
		return err
	}
	const atFDCWD = -100
	fd := atFDCWD
	_, _, e := syscall.Syscall6(sysRenameat2, uintptr(fd), uintptr(unsafe.Pointer(pa)),
		uintptr(fd), uintptr(unsafe.Pointer(pb)), renameExchange, 0)
	if e != 0 {
		return &linkError{"renameat2", a, b, e}
	}
	return nil
}

type linkError struct {
	op, a, b string
	err      syscall.Errno
}

func (e *linkError) Error() string { return e.op + " " + e.a + " " + e.b + ": " + e.err.Error() }

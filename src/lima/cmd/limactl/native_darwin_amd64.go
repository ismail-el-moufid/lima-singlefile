//go:build darwin && amd64 && cgo

package main

/*
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

int qemu_embedded_main(int argc, char **argv);
int qemu_img_embedded_main(int argc, char **argv);
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/lima-vm/lima/pkg/qemu/command"
)

func runNative(mode string, args []string) int {
	if C.pthread_main_np() != 1 {
		fmt.Fprintln(os.Stderr, "QEMU must start on the Darwin main thread")
		return 1
	}
	name := "qemu-system-x86_64"
	if mode == command.QEMUImg {
		name = "qemu-img"
	}
	values := append([]string{name}, args...)
	storage := C.calloc(C.size_t(len(values)+1), C.size_t(unsafe.Sizeof(uintptr(0))))
	if storage == nil {
		fmt.Fprintln(os.Stderr, "could not allocate QEMU arguments")
		return 1
	}
	defer C.free(storage)
	argv := unsafe.Slice((**C.char)(storage), len(values)+1)
	for i, value := range values {
		argv[i] = C.CString(value)
		defer C.free(unsafe.Pointer(argv[i]))
	}
	// Both the pointer array (including its NULL sentinel) and strings belong
	// to C. Native code may retain them for the dedicated worker's lifetime.
	var status C.int
	if mode == command.QEMUImg {
		status = C.qemu_img_embedded_main(C.int(len(values)), (**C.char)(storage))
	} else {
		status = C.qemu_embedded_main(C.int(len(values)), (**C.char)(storage))
	}
	// Go's os.Exit does not flush C stdio when a native entry point returns.
	C.fflush(nil)
	return int(status)
}

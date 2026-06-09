//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

type coord struct {
	X int16
	Y int16
}

type smallRect struct {
	Left   int16
	Top    int16
	Right  int16
	Bottom int16
}

type consoleScreenBufferInfo struct {
	Size              coord
	CursorPosition    coord
	Attributes        uint16
	Window            smallRect
	MaximumWindowSize coord
}

const (
	stdOutputHandle                 = uint32(-11 & 0xffffffff)
	enableVirtualTerminalProcessing = 0x0004
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procGetStdHandle               = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode             = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode             = kernel32.NewProc("SetConsoleMode")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
)

func initWindowsConsole() {
	handle, _, _ := procGetStdHandle.Call(uintptr(stdOutputHandle))
	if handle == 0 {
		return
	}
	var mode uint32
	r1, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if r1 == 0 {
		return
	}
	mode |= enableVirtualTerminalProcessing
	procSetConsoleMode.Call(handle, uintptr(mode))
}

func getTerminalSize() (width int, height int) {
	width = 80
	height = 24

	handle, _, _ := procGetStdHandle.Call(uintptr(stdOutputHandle))
	if handle != 0 {
		var info consoleScreenBufferInfo
		r1, _, _ := procGetConsoleScreenBufferInfo.Call(handle, uintptr(unsafe.Pointer(&info)))
		if r1 != 0 {
			width = int(info.Window.Right - info.Window.Left + 1)
			height = int(info.Window.Bottom - info.Window.Top + 1)
		}
	}
	if width < 50 {
		width = 50
	}
	if height < 10 {
		height = 10
	}
	return width, height
}

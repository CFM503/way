//go:build !windows

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func initWindowsConsole() {
	// No-op on non-Windows
}

func getTerminalSize() (width int, height int) {
	width = 80
	height = 24

	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err == nil {
		parts := strings.Fields(string(out))
		if len(parts) == 2 {
			h, errH := strconv.Atoi(parts[0])
			w, errW := strconv.Atoi(parts[1])
			if errH == nil && errW == nil {
				width = w
				height = h
			}
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

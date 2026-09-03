//go:build !linux

package main

import (
	"errors"
	"net"
)

// setPlatformSocketOptions is a no-op on non-Linux platforms
func setPlatformSocketOptions(conn net.Conn) {
	// No-op for Windows and macOS
}

// setTCPQuickAck is a no-op on non-Linux platforms
func setTCPQuickAck(conn net.Conn) {
	// No-op for Windows and macOS
}

// listenWithReusePort falls back to standard net.Listen on non-Linux platforms
func listenWithReusePort(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

// spliceRelay falls back to standard ReadFrom on non-Linux platforms
func spliceRelay(dst, src *net.TCPConn) (int64, error) {
	if dst == nil || src == nil {
		return 0, errors.New("nil TCPConn for relay")
	}
	return dst.ReadFrom(src)
}

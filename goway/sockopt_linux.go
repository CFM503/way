//go:build linux

package main

import (
	"errors"
	"net"
	"syscall"
)

// setPlatformSocketOptions enables Linux-specific high-performance socket options:
// - TCP_QUICKACK (12): disables delayed ACKs, eliminates 40ms latency spikes
func setPlatformSocketOptions(conn net.Conn) {
	tcpConn := extractTCPConn(conn)
	if tcpConn == nil {
		return
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return
	}
	_ = rawConn.Control(func(fd uintptr) {
		// TCP_QUICKACK is 12 on Linux
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 12, 1)
	})
}

// setTCPQuickAck reinforces quick acknowledgment on interactive flows
func setTCPQuickAck(conn net.Conn) {
	setPlatformSocketOptions(conn)
}

// listenWithReusePort creates a listener with SO_REUSEPORT enabled on Linux (kernel 3.9+)
func listenWithReusePort(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// SO_REUSEPORT is 15 on Linux
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	return lc.Listen(nil, network, address)
}

// spliceRelay performs kernel-level zero-copy transfer between two TCP sockets using Linux splice(2)
func spliceRelay(dst, src *net.TCPConn) (int64, error) {
	if dst == nil || src == nil {
		return 0, errors.New("nil TCPConn for splice")
	}
	return dst.ReadFrom(src)
}

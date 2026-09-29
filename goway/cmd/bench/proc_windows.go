//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

type procStat struct {
	cpuSec  float64 // kernel + user seconds
	peakRSS uint64  // peak working set bytes
}

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	psapi                   = syscall.NewLazyDLL("psapi.dll")
	procGetProcessTimes     = kernel32.NewProc("GetProcessTimes")
	procGetProcessMemory    = psapi.NewProc("GetProcessMemoryInfo")
	processQueryInformation = uint32(0x0400)
)

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

type filetime struct {
	Lo, Hi uint32
}

// stillActive is the WIN32 STILL_ACTIVE exit code.
const stillActive = 259

var procGetExitCodeProcess = kernel32.NewProc("GetExitCodeProcess")

// procAlive reports whether the process is still running. On Windows a
// terminated process we hold a handle for keeps its PID, so the exit code
// (STILL_ACTIVE) is the reliable liveness signal.
func procAlive(p *os.Process) bool {
	if p == nil {
		return false
	}
	h, err := syscall.OpenProcess(processQueryInformation, false, uint32(p.Pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	r1, _, _ := procGetExitCodeProcess.Call(uintptr(h), uintptr(unsafe.Pointer(&code)))
	return r1 != 0 && code == stillActive
}

func (f filetime) uint64() uint64 {
	return uint64(f.Hi)<<32 | uint64(f.Lo)
}

func procStatOf(p *os.Process) (procStat, error) {
	var s procStat
	if p == nil {
		return s, syscall.EINVAL
	}
	h, err := syscall.OpenProcess(processQueryInformation, false, uint32(p.Pid))
	if err != nil {
		return s, err
	}
	defer syscall.CloseHandle(h)

	var creation, exit, kernel, user filetime
	r1, _, callErr := procGetProcessTimes.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r1 == 0 {
		return s, callErr
	}
	ticks := kernel.uint64() + user.uint64() // 100ns units
	s.cpuSec = float64(ticks) / 1e7

	var mc processMemoryCounters
	mc.CB = uint32(unsafe.Sizeof(mc))
	r1, _, callErr = procGetProcessMemory.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&mc)),
		uintptr(unsafe.Sizeof(mc)),
	)
	if r1 == 0 {
		return s, callErr
	}
	s.peakRSS = uint64(mc.PeakWorkingSetSize)
	return s, nil
}

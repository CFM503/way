//go:build !windows

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type procStat struct {
	cpuSec  float64 // kernel + user seconds
	peakRSS uint64  // peak RSS bytes (VmHWM)
}

// procAlive reports whether the process is still running. A terminated but
// unreaped child shows state Z (zombie) in /proc/<pid>/stat and must count
// as dead.
func procAlive(p *os.Process) bool {
	if p == nil {
		return false
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.Pid))
	if err != nil {
		return false
	}
	line := string(stat)
	i := strings.LastIndex(line, ")")
	if i < 0 || i+2 >= len(line) {
		return false
	}
	return line[i+2] != 'Z'
}

// procStatOf reads /proc/<pid>/stat and /proc/<pid>/status. Clock ticks
// are assumed to be 100 Hz (getconf CLK_TCK on every mainstream distro).
func procStatOf(p *os.Process) (procStat, error) {
	var s procStat
	if p == nil {
		return s, fmt.Errorf("nil process")
	}
	pid := strconv.Itoa(p.Pid)

	stat, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return s, err
	}
	// Fields after the parenthesised comm: utime is field 14, stime 15
	// (1-indexed including comm).
	line := string(stat)
	if i := strings.LastIndex(line, ")"); i >= 0 {
		fields := strings.Fields(line[i+1:])
		// fields[0] is field 3 (state); utime = field 14 => index 11.
		if len(fields) >= 13 {
			ut, _ := strconv.ParseUint(fields[11], 10, 64)
			st, _ := strconv.ParseUint(fields[12], 10, 64)
			s.cpuSec = float64(ut+st) / 100.0
		}
	}

	status, err := os.ReadFile("/proc/" + pid + "/status")
	if err == nil {
		for _, l := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(l, "VmHWM:") {
				kbStr := strings.Fields(l)
				if len(kbStr) >= 2 {
					if kb, err := strconv.ParseUint(kbStr[1], 10, 64); err == nil {
						s.peakRSS = kb * 1024
					}
				}
				break
			}
		}
	}
	return s, nil
}

//go:build !windows

package sysinfo

import "runtime"

func domain() string { return "" }

func osVersion() string { return runtime.GOOS }

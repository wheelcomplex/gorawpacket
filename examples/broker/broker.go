/*

raw udp socket broker

must run as root for raw socket syscall

*/

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/droundy/goopt"
	"github.com/wheelcomplex/gorawpacket"
)

//
var configBrokerIpPort = goopt.String([]string{"-l", "--listen"}, "0.0.0.0:19", "listen udp address, default: 0.0.0.0:19")
var configMaxIdle = goopt.Int([]string{"-t", "--timeout"}, 60, "io worker idle timeout seconds, default: 60")
var configCpus = goopt.Int([]string{"-c", "--cpu"}, 0, "using CPUs, 0 for auto, -1 for all, default: 0")

//
func setGOMAXPROCS(use_cpu_num int) (rcpu int) {
	switch {
	case use_cpu_num <= -1:
		rcpu = runtime.NumCPU()
	case use_cpu_num == 0 && runtime.NumCPU() > 1:
		rcpu = runtime.NumCPU() - 1
	case runtime.NumCPU() >= use_cpu_num:
		rcpu = use_cpu_num
	case runtime.NumCPU() < use_cpu_num:
		rcpu = runtime.NumCPU()
		fmt.Fprintf(os.Stderr, "WARNING: execpt %d CPU to run, but onely %d CPU present.", use_cpu_num, runtime.NumCPU())
	}
	runtime.GOMAXPROCS(rcpu)
	return rcpu
}

//
func main() {
	goopt.Description = func() string {
		return "raw udp socket broker, relay udp message from/to special network interface by raw socket."
	}
	goopt.Version = "1.0"
	goopt.Summary = "raw udp socket broker"
	goopt.Parse(nil)
	rcpu := setGOMAXPROCS(*configCpus)
	fmt.Fprintf(os.Stderr, "%s ver %s, cpus %d/%d, listener(%d) %s ...\n", goopt.Summary, goopt.Version, runtime.GOMAXPROCS(-1), runtime.NumCPU(), configMaxIdle, configBrokerIpPort)
	if err := gorawpacket.BrokerRun(configBrokerIpPort, configMaxIdle); err != nil {
		fmt.Fprintf(os.Stderr, "BrokerRun: %s\n", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

//

// Copyright 2009 Anh Hai Trinh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// An efficient Eratosthenesque prime sieve using channels.
// This version uses wheel optimization and faster implementations
// of heap and sendproxy.

// Print all primes <= n, where n := flag.Arg(0).
// If the flag -n is given, it will print the nth prime only.

package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"container/heap"
	"container/ring"
	"github.com/droundy/goopt"
)

//
var nth = goopt.String([]string{"-m", "--mode"}, "quiet", "print the nth prime only, default: verbose")
var nCPU = goopt.Int([]string{"-c", "--cpu"}, -1, "number of CPUs to use, 0 for auto, -1 for all cpus, default: -1")
var nMin = goopt.Int([]string{"-l", "--less"}, 0, "display prime >= nMin only, default: 10240")

// Wheel to quickly generate numbers coprime to 2, 3, 5 and 7.
// Starting from 13, we successively add wheel[i] to get 17, 19, 23, ...
var wheel = []int{
	4, 2, 4, 6, 2, 6, 4, 2, 4, 6, 6, 2, 6, 4, 2, 6, 4, 6, 8, 4, 2, 4, 2, 4, 8,
	6, 4, 6, 2, 4, 6, 2, 6, 6, 4, 2, 4, 6, 2, 6, 4, 2, 4, 2, 10, 2, 10, 2,
}

// Return a chan int of values (n + k * wheel[i]) for successive i.
func spin(n, k, i, bufsize int) chan int {
	out := make(chan int, bufsize)
	go func() {
		for {
			for ; i < 48; i++ {
				out <- n
				n += k * wheel[i]
			}
			i = 0
		}
	}()
	return out
}

// Return a chan of numbers coprime to 2, 3, 5 and 7, starting from 13.
// coprime2357() -> 13, 17, 19, 23, 25, 31, 35, 37, 41, 47, ...
func coprime2357() chan int { return spin(13, 1, 0, 1024) }

// Map (p % 210) to a corresponding wheel position.
// A prime number can only be one of these value (mod 210).
var wheelpos = map[int]int{
	1: 46, 11: 47, 13: 0, 17: 1, 19: 2, 23: 3, 29: 4, 31: 5, 37: 6, 41: 7,
	43: 8, 47: 9, 53: 10, 59: 11, 61: 12, 67: 13, 71: 14, 73: 15, 79: 16,
	83: 17, 89: 18, 97: 19, 101: 20, 103: 21, 107: 22, 109: 23, 113: 24,
	121: 25, 127: 26, 131: 27, 137: 28, 139: 29, 143: 30, 149: 31, 151: 32,
	157: 33, 163: 34, 167: 35, 169: 36, 173: 37, 179: 38, 181: 39, 187: 40,
	191: 41, 193: 42, 197: 43, 199: 44, 209: 45,
}

// Return a chan of multiples of a prime p that are relative prime
// to 2, 3, 5 and 7, starting from (p * p).
// multiples(11) -> 121, 143, 187, 209, 253, 319, 341, 407, 451, 473, ...
// multiples(13) -> 169, 221, 247, 299, 377, 403, 481, 533, 559, 611, ...
func multiples(p int) chan int { return spin(p*p, p, wheelpos[p%210], 1024) }

type PeekCh struct {
	head int
	ch   chan int
}

// Heap of PeekCh, sorting by head values.
type PeekChHeap []*PeekCh

func (h PeekChHeap) Len() int {
	return len(h)
}

func (h PeekChHeap) Less(i, j int) bool {
	return h[i].head < h[j].head
}

func (h PeekChHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *PeekChHeap) Pop() (v interface{}) {
	*h, v = (*h)[:h.Len()-1], (*h)[h.Len()-1]
	return
}

func (h *PeekChHeap) Push(v interface{}) {
	*h = append(*h, v.(*PeekCh))
}

// Return a channel which serves as a sending proxy to `out`.
// Use a goroutine to receive values from `out` and store them
// in an expanding buffer, so that sending to `out` never blocks.
// See this discussion:
// <http://rogpeppe.wordpress.com/2010/02/10/unlimited-buffering-with-low-overhead>
func sendproxy(out chan<- int) chan<- int {
	proxy := make(chan int, 1024)
	go func() {
		n := 1024 // the allocated size of the circular queue
		first := ring.New(n)
		last := first
		var c chan<- int
		var e int
		for {
			c = out
			if first == last {
				// buffer empty: disable output
				c = nil
			} else {
				e = first.Value.(int)
			}
			select {
			case e = <-proxy:
				last.Value = e
				if last.Next() == first {
					// buffer full: expand it
					last.Link(ring.New(n))
					n *= 2
				}
				last = last.Next()
			case c <- e:
				first = first.Next()
			}
		}
	}()
	return proxy
}

// Return a chan int of primes.
func Sieve() chan int {
	// The output values.
	out := make(chan int, 1024)
	out <- 2
	out <- 3
	out <- 5
	out <- 7
	out <- 11

	// The channel of all composites to be eliminated in increasing order.
	composites := make(chan int, 8046)

	// The feedback loop.
	primes := make(chan int, 1024)
	primes <- 11

	// Merge channels of multiples of `primes` into `composites`.
	go func() {
		h := make(PeekChHeap, 0, 8046)
		min := 143
		for {
			m := multiples(<-primes)
			head := <-m
			for min < head {
				composites <- min
				minchan := heap.Pop(&h).(*PeekCh)
				min = minchan.head
				minchan.head = <-minchan.ch
				heap.Push(&h, minchan)
			}
			for min == head {
				minchan := heap.Pop(&h).(*PeekCh)
				min = minchan.head
				minchan.head = <-minchan.ch
				heap.Push(&h, minchan)
			}
			composites <- head
			heap.Push(&h, &PeekCh{<-m, m})
		}
	}()

	// Sieve out `composites` from `candidates`.
	go func() {
		// In order to generate the nth prime we only need multiples of
		// primes ≤ sqrt(nth prime).  Thus, the merging goroutine will
		// receive from this channel much slower than this goroutine
		// will send to it, making the buffer accumulates and blocks this
		// goroutine from sending to `primes`, causing a deadlock.  The
		// solution is to use a proxy goroutine to do automatic buffering.
		primes := sendproxy(primes)

		candidates := coprime2357()
		p := <-candidates

		for {
			c := <-composites
			for p < c {
				primes <- p
				out <- p
				p = <-candidates
			}
			if p == c {
				p = <-candidates
			}
		}
	}()

	return out
}
func setGOMAXPROCS(use_cpu_num int) (rcpu int) {
	if runtime.NumCPU() > 1 {
		switch {
		case use_cpu_num <= -1:
			rcpu = runtime.NumCPU()
		case use_cpu_num == 0:
			rcpu = runtime.NumCPU() - 1
		case runtime.NumCPU() >= use_cpu_num:
			rcpu = use_cpu_num
		case runtime.NumCPU() < use_cpu_num:
			rcpu = runtime.NumCPU()
			fmt.Fprintf(os.Stderr, "WARNING: execpt %d CPU to run, but onely %d CPU present.", use_cpu_num, runtime.NumCPU())
		}
	} else {
		rcpu = runtime.NumCPU()
		fmt.Fprintf(os.Stderr, "WARNING: onely %d CPU present.", rcpu)
	}
	runtime.GOMAXPROCS(rcpu)
	return rcpu
}
func stats(in, count chan int, maxCPU int) {
	var preCnt int = 0
	var qps float32 = 0
	var preQps float32 = 0
	var onePrime int
	var primeCount int
	var chgdir string
	var curCPU int = 0
	var chgcpu int = -1
	ioTk := time.NewTicker(1e9 * 5)
	defer func() {
		ioTk.Stop()
	}()
	ts := time.Now()
	if maxCPU > 0 {
		curCPU = maxCPU
		runtime.GOMAXPROCS(curCPU)
	}
	for {
		select {
		case onePrime = <-in:
		default:
		}
		select {
		case primeCount = <-count:
		default:
		}
		qps = (float32(primeCount) - float32(preCnt)) / float32(5)
		switch {
		case preQps == qps:
			chgdir = "=="
		case preQps > qps:
			chgdir = "<="
		default:
			chgdir = "=>"
		}
		preQps = qps
		preCnt = primeCount
		fmt.Fprintf(os.Stderr, "[%s] %03d/%03d, QPS(total: %020d, last: %020d, %014x): %012f %s %012f\r\n", ts.Format(time.RFC1123), runtime.GOMAXPROCS(-1), maxCPU, primeCount, onePrime, onePrime, qps, chgdir, preQps)
		ts = <-ioTk.C
		if maxCPU > 0 {
			switch {
			case curCPU >= maxCPU:
				chgcpu = -1
			case curCPU <= 1:
				chgcpu = 1
			}
			curCPU = curCPU + chgcpu
			runtime.GOMAXPROCS(curCPU)
		}
	}
}
func main() {
	goopt.Parse(nil)
	rcpu := setGOMAXPROCS(*nCPU)
	fmt.Fprintf(os.Stderr, "min: %d, mode: %s, cpus: %d/%d\n", *nMin, *nth, runtime.GOMAXPROCS(-1), runtime.NumCPU())
	primes := Sieve()
	var primeCount int = 0
	in := make(chan int, 1)
	count := make(chan int, 1)
	go stats(in, count, rcpu)
	for {
		p := <-primes
		primeCount++
		select {
		case count <- primeCount:
		default:
		}
		select {
		case in <- p:
		default:
		}
		if p <= *nMin {
			if *nth == "verbose" {
				fmt.Printf("%020d,%020d, %014x\n", primeCount, p, p)
			}
		} else {
			fmt.Printf("%020d,%020d, %014x\n", primeCount, p, p)
			//return
		}
	}
	/*
		CPU: Intel(R) Core(TM) i7-2630QM CPU @ 2.00GHz
		//TODO: better multiCore usage
	*/
}

// Copyright Yahoo. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
// Author: arnej

package jvm

import (
	"fmt"
	"strings"

	"github.com/vespa-engine/vespa/client/go/trace"
	"github.com/vespa-engine/vespa/client/go/util"
)

const (
	PowerOfTwo10 = 1 << 10
	PowerOfTwo20 = 1 << 20
)

func (opts *Options) getOrSetHeapKb(prefix string, heapKb int) int {
	var missing bool = true
	for _, x := range opts.jvmArgs {
		if strings.HasPrefix(x, prefix) {
			missing = false
			var val int
			var suffix rune
			n, err := fmt.Sscanf(x, prefix+"%d%c", &val, &suffix)
			if n == 2 && err == nil {
				switch suffix {
				case 'k':
					heapKb = val
				case 'm':
					heapKb = val * PowerOfTwo10
				case 'g':
					heapKb = val * PowerOfTwo20
				}
			}
		}
	}
	if missing {
		suffix := "k"
		newVal := heapKb
		if (newVal % PowerOfTwo20) == 0 {
			suffix = "g"
			newVal /= PowerOfTwo20
		} else if (newVal % PowerOfTwo10) == 0 {
			suffix = "m"
			newVal /= PowerOfTwo10
		}
		opts.AppendOption(fmt.Sprintf("%s%d%s", prefix, newVal, suffix))
	}
	return heapKb
}

func (opts *Options) CurMinHeapKb(fallback int) int {
	return opts.getOrSetHeapKb("-Xms", fallback)
}

func (opts *Options) CurMaxHeapKb(fallback int) int {
	return opts.getOrSetHeapKb("-Xmx", fallback)
}

func (opts *Options) AddDefaultHeapSizeArgs(minHeapKb, maxHeapKb int) {
	trace.Trace("AddDefaultHeapSizeArgs", minHeapKb, "/", maxHeapKb)
	minHeapKb = opts.CurMinHeapKb(minHeapKb)
	maxHeapKb = opts.CurMaxHeapKb(maxHeapKb)
	opts.MaybeAddHugepages(maxHeapKb)
}

func (opts *Options) MaybeAddHugepages(maxHeapKb int) {
	thpSizeKb := util.GetThpSizeKb()
	if thpSizeKb*2 < maxHeapKb {
		trace.Trace("add UseTransparentHugePages, thpSize", thpSizeKb, "* 2 < maxHeap", maxHeapKb)
		opts.AddOption("-XX:+UseTransparentHugePages")
	} else {
		trace.Trace("no UseTransparentHugePages, thpSize", thpSizeKb, "* 2 >= maxHeap", maxHeapKb)
	}
}

func adjustAvailableMemory(measured int) int {
	reserved := 1024
	need_min := 64
	if measured > need_min+2*reserved {
		return measured - reserved
	}
	if measured > need_min {
		return (measured + need_min) / 2
	}
	return need_min
}

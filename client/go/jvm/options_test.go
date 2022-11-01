// Copyright Yahoo. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package jvm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	aa = 123 * PowerOfTwo10
	bb = 234 * PowerOfTwo10
	cc = 456 * PowerOfTwo10
	dd = 567 * PowerOfTwo10
	ee = 16 * PowerOfTwo20
	ff = 31 * PowerOfTwo20
)

func TestHeapKbSimple(t *testing.T) {
	o := NewOptions(NewStandaloneContainer("foo"))
	assert.Equal(t, aa, o.CurMinHeapKb(aa))
	assert.Equal(t, bb, o.CurMaxHeapKb(bb))
	assert.Equal(t, 2, len(o.jvmArgs))
	assert.Equal(t, "-Xms123m", o.jvmArgs[0])
	assert.Equal(t, "-Xmx234m", o.jvmArgs[1])
}

func TestHeapKbMulti(t *testing.T) {
	o := NewOptions(NewStandaloneContainer("foo"))
	assert.Equal(t, aa, o.CurMinHeapKb(aa))
	assert.Equal(t, aa, o.CurMaxHeapKb(aa))
	assert.Equal(t, 2, len(o.jvmArgs))
	o.AppendOption("-Xms234m")
	o.AppendOption("-Xmx456m")
	assert.Equal(t, 4, len(o.jvmArgs))
	assert.Equal(t, bb, o.CurMinHeapKb(aa))
	assert.Equal(t, bb, o.CurMinHeapKb(dd))
	assert.Equal(t, cc, o.CurMaxHeapKb(aa))
	assert.Equal(t, cc, o.CurMaxHeapKb(dd))
	o.AppendOption("-Xms1g")
	o.AppendOption("-Xmx2g")
	assert.Equal(t, 1*PowerOfTwo20, o.CurMinHeapKb(aa))
	assert.Equal(t, 2*PowerOfTwo20, o.CurMaxHeapKb(aa))
	o.AppendOption("-Xms16777216k")
	o.AppendOption("-Xmx32505856k")
	assert.Equal(t, ee, o.CurMinHeapKb(aa))
	assert.Equal(t, ff, o.CurMaxHeapKb(aa))
}

func TestHeapKbAdd(t *testing.T) {
	o := NewOptions(NewStandaloneContainer("foo"))
	o.AddDefaultHeapSizeArgs(12345*PowerOfTwo10, 23456*PowerOfTwo10)
	assert.Equal(t, 3, len(o.jvmArgs))
	assert.Equal(t, "-Xms12345m", o.jvmArgs[0])
	assert.Equal(t, "-Xmx23456m", o.jvmArgs[1])
	assert.Equal(t, "-XX:+UseTransparentHugePages", o.jvmArgs[2])
}

func TestHeapKbNoAdd(t *testing.T) {
	o := NewOptions(NewStandaloneContainer("foo"))
	o.AppendOption("-Xms128k")
	o.AppendOption("-Xmx1280k")
	o.AddDefaultHeapSizeArgs(234, 345)
	assert.Equal(t, 2, len(o.jvmArgs))
	assert.Equal(t, "-Xms128k", o.jvmArgs[0])
	assert.Equal(t, "-Xmx1280k", o.jvmArgs[1])
}

package main

// The coders of github.com/lesismal/arpcex/extension/middleware/coder (gzip and the value
// appender), ported as they are from lesismal/arpc's Message to fib's arpc.Message: the wire
// layout and flag bits are the same, so a akio-arpc peer with Gzip and Appender reads them.

import (
	"bytes"
	"compress/gzip"
	"io"
	"sync/atomic"

	"github.com/lesismal/fib/arpc"
)

const (
	flagBitTracing = 0
	flagBitGZip    = 7
)

// gzipCoder is arpcex's coder/gzip.Gzip; decoded counts the compressed frames it inflated.
type gzipCoder struct {
	threshold int
	decoded   atomic.Int64
}

func (g *gzipCoder) Encode(_ *arpc.Client, msg *arpc.Message) *arpc.Message {
	if len(msg.Buffer) > g.threshold && !msg.IsFlagBitSet(flagBitGZip) {
		var in bytes.Buffer
		w := gzip.NewWriter(&in)
		_, _ = w.Write(msg.Buffer[arpc.HeaderIndexReserved+1:])
		_ = w.Close()
		buf := in.Bytes()
		total := len(buf) + arpc.HeaderIndexReserved + 1
		if total < len(msg.Buffer) {
			copy(msg.Buffer[arpc.HeaderIndexReserved+1:], buf)
			msg.Buffer = msg.Buffer[:total]
			msg.SetBodyLen(total - 16)
			_ = msg.SetFlagBit(flagBitGZip, true)
		}
	}
	return msg
}

func (g *gzipCoder) Decode(_ *arpc.Client, msg *arpc.Message) *arpc.Message {
	if msg.IsFlagBitSet(flagBitGZip) {
		r, err := gzip.NewReader(bytes.NewReader(msg.Buffer[arpc.HeaderIndexReserved+1:]))
		if err != nil {
			return msg
		}
		buf, err := io.ReadAll(r)
		if err == nil {
			g.decoded.Add(1)
			msg.Buffer = append(msg.Buffer[:arpc.HeaderIndexReserved+1], buf...)
			_ = msg.SetFlagBit(flagBitGZip, false)
			msg.SetBodyLen(len(msg.Buffer) - 16)
		}
	}
	return msg
}

// appender is arpcex's coder.Appender with string values.
type appender struct {
	name string
	bit  int
}

func (ap *appender) Encode(_ *arpc.Client, msg *arpc.Message) *arpc.Message {
	value, ok := msg.Get(ap.name)
	if !ok {
		return msg
	}
	if err := msg.SetFlagBit(ap.bit, true); err != nil {
		return msg
	}
	valueData := []byte(value.(string))
	key := ap.name
	msg.Buffer = append(msg.Buffer, make([]byte, len(key)+len(valueData)+2)...)
	appendData := msg.Buffer[len(msg.Buffer)-len(key)-len(valueData)-2:]
	copy(appendData, key)
	copy(appendData[len(key):], valueData)
	appendLen := uint16(len(appendData))
	appendData[appendLen-2], appendData[appendLen-1] = byte(appendLen>>8), byte(appendLen&0xFF)
	msg.SetBodyLen(len(msg.Buffer) - 16)
	return msg
}

func (ap *appender) Decode(_ *arpc.Client, msg *arpc.Message) *arpc.Message {
	if msg.IsFlagBitSet(ap.bit) {
		bufLen := len(msg.Buffer)
		if bufLen > 2 {
			key := ap.name
			appendLen := (int(msg.Buffer[bufLen-2]) << 8) | int(msg.Buffer[bufLen-1])
			if bufLen >= appendLen {
				if string(msg.Buffer[bufLen-appendLen:bufLen-appendLen+len(key)]) != key {
					return msg
				}
				msg.Set(key, string(msg.Buffer[bufLen-appendLen+len(key):bufLen-2]))
			}
			msg.Buffer = msg.Buffer[:len(msg.Buffer)-appendLen]
			_ = msg.SetFlagBit(ap.bit, false)
			msg.SetBodyLen(len(msg.Buffer) - 16)
		}
	}
	return msg
}

// useCoders adds the chain both sides of the coded checks use: values, then gzip.
func useCoders(h *arpc.Handler) *gzipCoder {
	g := &gzipCoder{threshold: 256}
	h.UseCoder(&appender{name: "trace", bit: flagBitTracing})
	h.UseCoder(g)
	return g
}

package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDNSFallsBackToTCPAfterUDPTimeout(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	dev, n, err := CreateNetTUN([]netip.Addr{ip}, []netip.Addr{ip}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	udp, err := n.ListenUDPAddrPort(netip.AddrPortFrom(ip, 53))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close() // deliberately silent
	tcp, err := n.ListenTCPAddrPort(netip.AddrPortFrom(ip, 53))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		c, e := tcp.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		hdr := make([]byte, 2)
		if _, e = io.ReadFull(c, hdr); e != nil {
			return
		}
		b := make([]byte, binary.BigEndian.Uint16(hdr))
		if _, e = io.ReadFull(c, b); e != nil {
			return
		}
		b[2] |= 0x80
		b[3] |= 0x80
		c.Write(append(hdr, b...))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA}
	_, h, err := n.exchange(ctx, ip, q, 500*time.Millisecond)
	if err != nil || !h.Response {
		t.Fatalf("TCP fallback failed: %v %+v", err, h)
	}
}

func TestDNSFallbackErrorPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"socket timeout", &net.OpError{Op: "read", Err: context.DeadlineExceeded}, true},
		{"wrapped deadline", fmt.Errorf("query: %w", context.DeadlineExceeded), true},
		{"non-timeout I/O", io.ErrUnexpectedEOF, false},
		{"malformed response", errCannotUnmarshalDNSMessage, false},
		{"cancelled attempt", context.Canceled, false},
		{"other error", errors.New("unreachable"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryDNSTimeout(context.Background(), tc.err); got != tc.want {
				t.Fatalf("retry=%v, want %v", got, tc.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if retryDNSTimeout(ctx, context.DeadlineExceeded) {
		t.Fatal("cancelled parent must not retry")
	}
}

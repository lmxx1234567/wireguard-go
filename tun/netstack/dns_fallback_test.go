package netstack

import (
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
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

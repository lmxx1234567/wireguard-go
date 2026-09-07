package main

import (
	"context"
	"errors"
	"net"
	"testing"
)

type fakeTunnel struct {
	calls   []string
	answers []string
}

func (f *fakeTunnel) LookupContextHost(context.Context, string) ([]string, error) {
	return f.answers, nil
}
func (f *fakeTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	f.calls = append(f.calls, addr)
	if len(f.calls) == 1 {
		return nil, errors.New("unreachable")
	}
	a, b := net.Pipe()
	b.Close()
	return a, nil
}
func TestResolverRetainsAndRetriesAddresses(t *testing.T) {
	f := &fakeTunnel{answers: []string{"2001:db8::1", "192.0.2.1"}}
	ctx, ip, err := (netstackResolver{f}).Resolve(context.Background(), "example.com")
	if err != nil || ip.String() != "192.0.2.1" {
		t.Fatalf("%v %v", ip, err)
	}
	c, err := dialResolved(ctx, "tcp", net.JoinHostPort(ip.String(), "443"), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(f.calls) != 2 || f.calls[1] != "[2001:db8::1]:443" {
		t.Fatal(f.calls)
	}
}
func TestCancelledDialDoesNotAttempt(t *testing.T) {
	f := &fakeTunnel{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), resolvedAddressesKey{}, []string{"192.0.2.1"}))
	cancel()
	_, err := dialResolved(ctx, "tcp", "192.0.2.1:443", f)
	if !errors.Is(err, context.Canceled) || len(f.calls) != 0 {
		t.Fatalf("%v %v", err, f.calls)
	}
}

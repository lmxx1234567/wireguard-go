package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type fakeTunnel struct {
	calls   []string
	answers []string
	dial    func(context.Context, string) (net.Conn, error)
}

func (f *fakeTunnel) LookupContextHost(context.Context, string) ([]string, error) {
	return f.answers, nil
}
func (f *fakeTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	f.calls = append(f.calls, addr)
	if f.dial != nil {
		return f.dial(ctx, addr)
	}
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

func TestIPv6AttemptAfterFirstIPv4Timeout(t *testing.T) {
	f := &fakeTunnel{answers: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8", "2001:db8::1"}}
	f.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		if addr != "[2001:db8::1]:443" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	parent, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ctx, ip, err := (netstackResolver{f}).Resolve(parent, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	c, err := dialResolved(ctx, "tcp", net.JoinHostPort(ip.String(), "443"), f)
	if err != nil {
		t.Fatalf("IPv6 starved behind IPv4 answers: %v, attempts=%v", err, f.calls)
	}
	c.Close()
	if len(f.calls) != 2 || f.calls[1] != "[2001:db8::1]:443" {
		t.Fatal(f.calls)
	}
}

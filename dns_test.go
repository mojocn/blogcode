package blogcode

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDns(t *testing.T) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 2,
			}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}
	ip, err := r.LookupHost(context.Background(), "www.google.com")
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("%#v", ip)
}

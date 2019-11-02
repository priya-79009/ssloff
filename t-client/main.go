package main

import (
	"context"
	"flag"
	"github.com/account-login/ctxlog"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

type Reader struct {
	ctx   context.Context
	bps   int
	start time.Time
	n     int
}

func rateCtrl(start time.Time, n int, bps int) {
	expected := time.Duration(float64(time.Second) * float64(n) / float64(bps))
	actual := time.Now().Sub(start)
	if expected > actual {
		time.Sleep(expected - actual)
	}
}

func (rd *Reader) Read(buf []byte) (int, error) {
	rd.n += len(buf)
	ctxlog.Debugf(rd.ctx, "write %v", rd.n)
	rateCtrl(rd.start, rd.n, rd.bps)
	return len(buf), nil
}

func (rd *Reader) Close() error {
	return nil
}

func reader(ctx context.Context, reader io.Reader, bps int) {
	if bps == 0 {
		return
	}

	ctxlog.Debugf(ctx, "start reading [bps:%v]", bps)
	n := 0
	start := time.Now()
	buf := [100]byte{}
	for {
		nread, err := reader.Read(buf[:])
		if err != nil {
			ctxlog.Warnf(ctx, "reader err: %v", err)
			return
		}

		n += nread
		ctxlog.Debugf(ctx, "read %v", n)
		rateCtrl(start, n, bps)
	}
}

type DialContext interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func main() {
	log.SetFlags(log.Flags() | log.Lmicroseconds)
	ctx := context.Background()

	server := flag.String("server", "http://127.0.0.1:22080/", "upload to server")
	socks := flag.String("socks", "", "socks5 proxy")
	writeBPS := flag.Int("write", 0, "upload xxx bytes per second")
	readBPS := flag.Int("read", 0, "download xxx bytes per second")
	flag.Parse()

	c := http.Client{}

	// socks proxy
	if *socks != "" {
		dialer, err := proxy.SOCKS5("tcp", *socks, nil, proxy.Direct)
		if err != nil {
			ctxlog.Fatal(ctx, err)
			return
		}
		c.Transport = &http.Transport{DialContext: dialer.(DialContext).DialContext}
	}

	// uploader
	var stream io.ReadCloser
	if *writeBPS != 0 {
		stream = &Reader{ctx: ctx, bps: *writeBPS, start: time.Now()}
	}

	ctxlog.Infof(ctx, "request begin")
	resp, err := c.Post(*server, "application/octet-stream", stream)
	if err != nil {
		ctxlog.Fatal(ctx, err)
		return
	}
	ctxlog.Infof(ctx, "request done")

	defer resp.Body.Close()
	reader(ctx, resp.Body, *readBPS)
	ctxlog.Infof(ctx, "response read")
}

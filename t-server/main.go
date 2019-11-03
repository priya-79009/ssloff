package main

import (
	"context"
	"github.com/account-login/ctxlog"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

func atoi(s string, d int) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return d
	}
	return i
}

func rateCtrl(start time.Time, n int, bps int) {
	expected := time.Duration(float64(time.Second) * float64(n) / float64(bps))
	actual := time.Now().Sub(start)
	if expected > actual {
		time.Sleep(expected - actual)
	}
}

func reader(ctx context.Context, wg *sync.WaitGroup, reader io.Reader, bps int, step int) {
	defer wg.Done()
	if bps == 0 {
		return
	}

	ctxlog.Debugf(ctx, "start reading [bps:%v]", bps)
	n := 0
	start := time.Now()
	buf := make([]byte, step)
	for {
		nread, err := reader.Read(buf)
		if err != nil {
			ctxlog.Warnf(ctx, "reader err: %v", err)
			return
		}

		n += nread
		ctxlog.Debugf(ctx, "read %v", n)
		rateCtrl(start, n, bps)
	}
}

func writer(ctx context.Context, wg *sync.WaitGroup, writer io.Writer, bps int, step int) {
	defer wg.Done()
	if bps == 0 {
		return
	}

	ctxlog.Debugf(ctx, "start writing [bps:%v]", bps)
	n := 0
	start := time.Now()
	buf := make([]byte, step)
	for {
		nwritten, err := writer.Write(buf)
		if err != nil {
			ctxlog.Warnf(ctx, "writer err: %v", err)
			return
		}
		writer.(http.Flusher).Flush()

		n += nwritten
		ctxlog.Debugf(ctx, "written %v", n)
		rateCtrl(start, n, bps)
	}
}

func serve(res http.ResponseWriter, req *http.Request) {
	ctx := ctxlog.Pushf(req.Context(), "[client:%s]", req.RemoteAddr)
	q := req.URL.Query()
	readBPS := atoi(q.Get("read_bps"), 0)
	writeBPS := atoi(q.Get("write_bps"), 0)
	step := atoi(q.Get("step"), 100)

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go reader(ctx, wg, req.Body, readBPS, step)
	go writer(ctx, wg, res, writeBPS, step)
	wg.Wait()
}

func main() {
	log.SetFlags(log.Flags() | log.Lmicroseconds)

	s := &http.Server{
		Addr:              ":22080",
		Handler:           http.HandlerFunc(serve),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0,
		MaxHeaderBytes:    1 << 20,
	}
	ctxlog.Fatal(context.Background(), s.ListenAndServe())
}

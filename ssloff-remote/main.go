package main

import (
	"context"
	"flag"
	"github.com/account-login/ctxlog"
	"github.com/account-login/ssloff"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// logging
	log.SetFlags(log.Flags() | log.Lmicroseconds)

	// ctx
	ctx := context.Background()

	// args
	remote := ssloff.Remote{}
	flag.StringVar(&remote.RemoteAddr, "remote", "127.0.0.1:2180", "listen on this address")
	flag.BoolVar(&remote.PreferIPv4, "4", false, "prefer ipv4")
	debugServerPtr := flag.String("debug", "", "debug server addr")
	logfile := flag.String("log", "", "log file")
	flag.Parse()

	if *logfile != "" {
		f, err := os.OpenFile(*logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err == nil {
			defer f.Close()
			log.SetOutput(f)
		}
	}

	if *debugServerPtr != "" {
		_ = ssloff.StartDebugServer(ctx, *debugServerPtr)
	}

	// start remote
	if err := remote.Start(ctx); err != nil {
		ctxlog.Fatal(ctx, err)
		return
	}
	ctxlog.Infof(ctx, "listening on %v", remote.RemoteAddr)

	// exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	ctxlog.Infof(ctx, "exiting")
}

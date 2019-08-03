package ssloff

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/account-login/ctxlog"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type clientMetric struct {
	Id           uint32
	Target       string
	Accepted     int64
	FirstRead    int64
	FirstWrite   int64
	LastWrite    int64
	Closed       int64
	BytesRead    int
	BytesWritten int
}

type clientState struct {
	id     uint32
	conn   net.Conn
	remote *remoteState
	metric clientMetric
	// reader
	readerExit chan protoMsg
	readerDone chan struct{}
	// writer
	writerInput chan protoMsg
	writerExit  chan protoMsg
	writerDone  chan struct{}
}

type remoteState struct {
	conn         net.Conn
	mu           sync.Mutex
	clientIdSeq  uint32
	clientStates map[uint32]*clientState
	quiting      bool
	// reader
	readerExit chan protoMsg
	readerDone chan struct{}
	// writer
	writerInput chan protoMsg
	writerExit  chan protoMsg
	writerDone  chan struct{}
}

type Local struct {
	// params
	RemoteAddr string
	LocalAddr  string
	MITM       *MITM
	// *remoteState
	rstate atomic.Value
}

func (l *Local) Start(ctx context.Context) error {
	// listen for client
	listener, err := net.Listen("tcp", l.LocalAddr)
	if err != nil {
		return err
	}
	go l.clientAcceptor(ctx, listener)

	// connect to remote
	go l.remoteConnector(ctx)

	return nil
}

func (l *Local) clientAcceptor(ctx context.Context, listener net.Listener) {
	defer safeClose(ctx, listener)

	session := uint64(0)
	for {
		session++

		conn, err := listener.Accept()
		if err != nil {
			ctxlog.Errorf(ctx, "accept: %v", err)
			continue
		}

		ctx := ctxlog.Pushf(ctx, "[session:%v][client:%v]", session, conn.RemoteAddr())
		go l.clientInitializer(ctx, conn)
	}
}

func (l *Local) clientInitializer(ctx context.Context, conn net.Conn) {
	defer safeClose(ctx, conn)

	acceptedUs := time.Now().UnixNano() / 1000
	ctxlog.Infof(ctx, "accepted")

	// get remote state
	var r *remoteState
	if p := l.rstate.Load(); p != nil {
		r = p.(*remoteState)
	}
	if r == nil {
		ctxlog.Errorf(ctx, "remote not ready")
		return
	}

	// read socks5 req
	// TODO: io deadline
	reader := bufio.NewReaderSize(conn, kReaderBuf)
	dstAddr, dstPort, err := socks5handshake(readerWriter{reader, conn})
	if err != nil {
		ctxlog.Errorf(ctx, "%v", err)
		return
	}

	// detect ssl
	var tlsConn *tls.Conn
	// consume buffered data
	peekData := make([]byte, reader.Buffered())
	_, _ = reader.Read(peekData)
	if dstPort == 443 {
		// read more data
		if len(peekData) == 0 {
			peekData = make([]byte, kReaderBuf)
			n, err := conn.Read(peekData)
			if err != nil {
				ctxlog.Errorf(ctx, "peek for ssl handshake: %v", err)
				return
			}

			peekData = peekData[:n]
		}

		if host, ok := detectTLS(peekData); ok {
			// setup peekedConn
			if host == "" {
				host = dstAddr.String()
				ctxlog.Infof(ctx, "got tls without SNI [host:%v]", host)
			} else {
				ctxlog.Infof(ctx, "got tls SNI [host:%v]", host)
			}
			bottom := peekedConn{peeked: peekData, conn: conn}
			peekData = nil
			// create tls conn
			tlsConn = tls.Server(&bottom, l.MITM.TLSForHost(ctx, host))
			// fix dstAddr to domain name if tls host is domain name
			if dstAddr.atype != kSocksAddrDomain {
				if net.ParseIP(host) == nil {
					ctxlog.Infof(ctx, "fix [dst:%v] to [host:%v]", dstAddr, host)
					dstAddr = socksAddr{atype: kSocksAddrDomain, addr: []byte(host)}
				}
			}
		}
	}

	// create client
	client := r.clientNew(ctx)
	if client == nil {
		ctxlog.Errorf(ctx, "can not create clientState")
		return
	}

	// log
	ctx = ctxlog.Pushf(ctx, "[client][id:%v][target:%v:%v]", client.id, dstAddr, dstPort)
	ctxlog.Debugf(ctx, "created clientState")

	// setup client
	if tlsConn != nil {
		client.conn = tlsConn
	} else {
		client.conn = conn
	}
	client.metric.Id = client.id
	client.metric.Target = fmt.Sprintf("%s:%d", dstAddr, dstPort)
	client.metric.Accepted = acceptedUs

	// connect cmd
	var cmd uint32 = kClientInputConnect
	if tlsConn != nil {
		cmd = kClientInputConnectSSL
	}
	client.remote.writerInput <- protoMsg{
		cmd: cmd, cid: client.id, data: serializeSocksAddr(dstAddr, dstPort),
	}

	// peeked data
	if len(peekData) > 0 {
		ctxlog.Debugf(ctx, "client reader got %v bytes from peekData", len(peekData))
		client.remote.writerInput <- protoMsg{
			cmd: kClientInputUp, cid: client.id, data: peekData,
		}
		client.metric.FirstRead = time.Now().UnixNano() / 1000
		client.metric.BytesRead += len(peekData)
	}

	// start client io
	go client.clientReader(ctx)
	go client.clientWriter(ctx)

	// wait for client done
	<-client.readerDone
	<-client.writerDone

	// clear client state
	client.clientClose(ctx)
	ctxlog.Infof(ctx, "client done")
}

func (client *clientState) clientReader(ctx context.Context) {
	defer close(client.readerDone)

	ioInput, ioQuit := reader2chan(client.conn)
	defer close(ioQuit)
	for {
		select {
		case ev := <-ioInput:
			// eof
			if ev == nil {
				ctxlog.Infof(ctx, "client reader exit with EOF")
				client.remote.writerInput <- protoMsg{cmd: kClientInputUpEOF, cid: client.id}
				return
			}
			// io error
			if err, ok := ev.(error); ok {
				ctxlog.Errorf(ctx, "client reader exit with io error: %v", err)
				msg := protoMsg{cmd: kClientClose, cid: client.id}
				client.writerExit <- msg
				client.remote.writerInput <- msg
				return
			}

			data := ev.([]byte)
			if len(data) > kMsgRecvMaxLen {
				panic("ensure this")
			}

			// metric
			if client.metric.FirstRead == 0 {
				client.metric.FirstRead = time.Now().UnixNano() / 1000
			}
			client.metric.BytesRead += len(data)

			// send data to remote
			ctxlog.Debugf(ctx, "client reader got %v bytes", len(data))
			client.remote.writerInput <- protoMsg{cmd: kClientInputUp, cid: client.id, data: data}
		case ev := <-client.readerExit:
			if ev.cmd != kClientClose {
				panic("bad msg type")
			}
			ctxlog.Infof(ctx, "client reader exit with kClientClose")
			return
		}
	}
}

func (client *clientState) clientWriter(ctx context.Context) {
	defer close(client.writerDone)

	for {
		select {
		case ev := <-client.writerInput:
			// do io
			var err error
			switch ev.cmd {
			case kRemoteInputDown:
				ctxlog.Debugf(ctx, "client writer got %v bytes", len(ev.data))
				if client.metric.FirstWrite == 0 {
					client.metric.FirstWrite = time.Now().UnixNano() / 1000
				}
				client.metric.LastWrite = time.Now().UnixNano() / 1000
				client.metric.BytesWritten += len(ev.data)

				_, err = client.conn.Write(ev.data)
			case kRemoteInputDownEOF:
				err = client.conn.(interface{ CloseWrite() error }).CloseWrite() // assume tcp
			default:
				panic("bad msg type")
			}

			if err != nil {
				ctxlog.Errorf(ctx, "client writer exit with io error: %v", err)
				msg := protoMsg{cmd: kClientClose, cid: client.id}
				client.readerExit <- msg
				client.remote.writerInput <- msg
				return
			}

			if ev.cmd == kRemoteInputDownEOF {
				ctxlog.Infof(ctx, "client writer exit with EOF")
				return
			}
		case ev := <-client.writerExit:
			if ev.cmd != kClientClose {
				panic("bad msg type")
			}
			ctxlog.Infof(ctx, "client writer exit with kClientClose")
			return
		}
	}
}

func (client *clientState) clientClose(ctx context.Context) {
	// metric
	client.metric.Closed = time.Now().UnixNano() / 1000
	if metric, err := json.Marshal(client.metric); err == nil {
		ctxlog.Debugf(context.Background(), "METRIC %s", string(metric))
	}

	// erase from remote map
	client.remote.mu.Lock()
	defer client.remote.mu.Unlock()
	delete(client.remote.clientStates, client.id)

	if len(client.remote.clientStates) == 0 {
		ctxlog.Debugf(ctx, "i am the last client")
	}
}

func (r *remoteState) clientGet(id uint32) *clientState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clientStates[id]
}

func (r *remoteState) clientNew(ctx context.Context) *clientState {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.quiting {
		return nil
	}

	// find next id
	for _, ok := r.clientStates[r.clientIdSeq]; ok; r.clientIdSeq++ {
		ctxlog.Debugf(ctx, "[clientIdSeq:%v] overflowed", r.clientIdSeq)
	}

	// create clientState
	client := &clientState{
		id:          r.clientIdSeq,
		remote:      r,
		readerExit:  make(chan protoMsg, 4),
		readerDone:  make(chan struct{}),
		writerInput: make(chan protoMsg, kChannelSize),
		writerExit:  make(chan protoMsg, 4),
		writerDone:  make(chan struct{}),
	}
	r.clientStates[r.clientIdSeq] = client

	// next id
	r.clientIdSeq++
	return client
}

func (r *remoteState) remoteReader(ctx context.Context) {
	defer close(r.readerDone)

	reader := bufio.NewReaderSize(r.conn, kReaderBuf)
	ioInput, ioQuit := protoParser(reader)
	defer close(ioQuit)
	for {
		select {
		case ev := <-ioInput:
			// io error or eof
			if ev.err != nil {
				if ev.err != io.EOF {
					ctxlog.Errorf(ctx, "remote reader exit with io error: %v", ev.err)
				} else {
					ctxlog.Warnf(ctx, "remote reader exit with EOF")
				}
				r.writerExit <- protoMsg{cmd: kRemoteClose}
				return
			}
			ctxlog.Debugf(ctx, "[cid:%v][cmd:%v][data_len:%v]", ev.cid, ev.cmd, len(ev.data))

			client := r.clientGet(ev.cid)
			if client == nil {
				ctxlog.Warnf(ctx, "[cid:%v] not found", ev.cid)
				continue
			}

			switch ev.cmd {
			case kRemoteInputDown, kRemoteInputDownEOF:
				// FIXME: block on closed client?
				// TODO: timeout or flow ctrl
				client.writerInput <- protoMsg{cmd: ev.cmd, cid: ev.cid, data: ev.data}
			case kClientClose:
				msg := protoMsg{cmd: ev.cmd}
				client.writerExit <- msg
				client.readerExit <- msg
			default:
				ctxlog.Errorf(ctx, "[cid:%v] unknown [cmd:%v]", ev.cid, ev.cmd)
			}
		case ev := <-r.readerExit:
			if ev.cmd != kLocalClose {
				panic("bad msg type")
			}
			ctxlog.Infof(ctx, "remote reader exit with kLocalClose")
			return
		} // select
	} // for
}

func (r *remoteState) remoteWriter(ctx context.Context) {
	defer close(r.writerDone)

	for {
		select {
		case ev := <-r.writerInput:
			var msg protoMsg
			switch ev.cmd {
			case kClientClose:
				msg = protoMsg{cmd: kClientClose, cid: ev.cid}
			case kClientInputConnect, kClientInputConnectSSL:
				msg = protoMsg{cmd: ev.cmd, cid: ev.cid, data: ev.data}
			case kClientInputUp:
				if len(ev.data) > kMsgRecvMaxLen {
					panic("ensure this")
				}
				msg = protoMsg{cmd: kClientInputUp, cid: ev.cid, data: ev.data}
			case kClientInputUpEOF:
				msg = protoMsg{cmd: kClientInputUpEOF, cid: ev.cid}
			default:
				panic("bad msg type")
			}

			if err := msg.writeTo(r.conn); err != nil {
				ctxlog.Errorf(ctx, "remote write exit with io error: %v", err)
				r.readerExit <- protoMsg{cmd: kRemoteClose}
				return
			}
		case ev := <-r.writerExit:
			if ev.cmd != kRemoteClose {
				panic("bad msg type")
			}
			ctxlog.Infof(ctx, "remote writer exit with kRemoteClose")
			return
		}
	}
}

func (r *remoteState) remoteClose(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// set quiting flag
	r.quiting = true

	// notify all client to quit
	msg := protoMsg{cmd: kClientClose}
	for _, client := range r.clientStates {
		client.readerExit <- msg
		client.writerExit <- msg
	}
}

func (l *Local) remoteConnector(ctx context.Context) {
	session := uint64(0)
	for {
		session++
		ctx := ctxlog.Pushf(ctx, "[rsession:%v]", session)

		l.remoteInitializer(ctx)

		ctxlog.Warnf(ctx, "reconnecting after 1s")
		time.Sleep(1 * time.Second)
	}
}

func (l *Local) remoteInitializer(ctx context.Context) {
	// TODO: io timeout
	conn, err := net.Dial("tcp", l.RemoteAddr)
	if err != nil {
		ctxlog.Errorf(ctx, "connect remote: %v", err)
		return
	}
	defer safeClose(ctx, conn)

	ctxlog.Infof(ctx, "[remote:%v] connected from [local:%v]", l.RemoteAddr, conn.LocalAddr())

	remote := &remoteState{
		conn:         conn,
		clientIdSeq:  1,
		clientStates: map[uint32]*clientState{},
		readerExit:   make(chan protoMsg, 4),
		readerDone:   make(chan struct{}),
		writerInput:  make(chan protoMsg, kChannelSize),
		writerExit:   make(chan protoMsg, 4),
		writerDone:   make(chan struct{}),
	}

	// init remote
	go remote.remoteReader(ctx)
	go remote.remoteWriter(ctx)

	// store remote
	l.rstate.Store(remote)

	// wait remote down
	<-remote.readerDone
	<-remote.writerDone

	// clear remote state
	l.rstate.Store((*remoteState)(nil))
	remote.remoteClose(ctx)
}

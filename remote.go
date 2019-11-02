package ssloff

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/account-login/ctxlog"
	"github.com/pkg/errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type Remote struct {
	// param
	RemoteAddr string
	PreferIPv4 bool
}

type localState struct {
	r    *Remote
	conn net.Conn
	// reader
	readerExit chan protoMsg
	readerDone chan struct{}
	// writer
	thead        *targetState
	ttail        *targetState
	writerNotify chan struct{}
	//writerInput  chan protoMsg // xxx
	writerExit chan protoMsg
	writerDone chan struct{}
	// targets
	mu           sync.Mutex
	targetStates map[uint32]*targetState
	quiting      bool
}

type targetMetric struct {
	Id           uint32
	Target       string
	Created      int64
	Connected    int64
	FirstWrite   int64
	FirstRead    int64
	LastRead     int64
	Closed       int64
	BytesRead    int
	BytesWritten int
}

type targetState struct {
	id     uint32
	conn   net.Conn
	local  *localState
	metric targetMetric
	// reader
	readerExit chan protoMsg
	readerDone chan struct{}
	// writer
	writerInput chan protoMsg
	writerExit  chan protoMsg
	writerDone  chan struct{}
	// local writer queue
	mu    sync.Mutex
	cond  sync.Cond
	phead *protoMsg
	ptail *protoMsg
	// notified target queue, protected by localState.mu
	tnext    *targetState
	notified bool
	// flow control
	fc FlowCtrl
}

func (r *Remote) Start(ctx context.Context) error {
	// listen for local
	listener, err := net.Listen("tcp", r.RemoteAddr)
	if err != nil {
		return err
	}

	go r.localAcceptor(ctx, listener)
	return nil
}

func (r *Remote) localAcceptor(ctx context.Context, listener net.Listener) {
	defer safeClose(ctx, listener)

	session := uint64(0)
	for {
		session++

		conn, err := listener.Accept()
		if err != nil {
			ctxlog.Errorf(ctx, "accept: %v", err)
			continue
		}

		ctx := ctxlog.Pushf(ctx, "[session:%v][local:%v]", session, conn.RemoteAddr())
		go r.localInitializer(ctx, conn)
	}
}

func (r *Remote) localInitializer(ctx context.Context, conn net.Conn) {
	defer safeClose(ctx, conn)

	ctxlog.Infof(ctx, "accepted")

	// create localState
	l := &localState{
		r:            r,
		conn:         conn,
		readerExit:   make(chan protoMsg, 4),
		readerDone:   make(chan struct{}),
		writerNotify: make(chan struct{}, 1),
		writerExit:   make(chan protoMsg, 4),
		writerDone:   make(chan struct{}),
		targetStates: map[uint32]*targetState{},
	}

	// start io
	go l.localReader(ctx)
	go l.localWriter(ctx)

	// wait for reader and writer
	<-l.readerDone
	<-l.writerDone

	// clear local state
	l.localClose(ctx)
	ctxlog.Infof(ctx, "done")
}

func (l *localState) targetGet(cid uint32) *targetState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.targetStates[cid]
}

func (l *localState) localReader(ctx context.Context) {
	defer close(l.readerDone)

	reader := bufio.NewReaderSize(l.conn, kReaderBuf)
	ioInput, ioQuit := protoParser(reader)
	defer close(ioQuit)
	for {
		select {
		case ev := <-ioInput:
			// io error or eof
			if ev.err != nil {
				if ev.err != io.EOF {
					ctxlog.Errorf(ctx, "local reader exit with io error: %v", ev.err)
				} else {
					ctxlog.Warnf(ctx, "local reader exit with EOF")
				}
				l.writerExit <- protoMsg{cmd: kLocalClose}
				return
			}

			ctxlog.Debugf(ctx, "[cid:%v][cmd:%v][ack:%v][data_len:%v]",
				ev.cid, ev.cmd, ev.ack, len(ev.data))

			switch ev.cmd {
			case kClientInputConnect, kClientInputConnectSSL:
				err := func() error {
					// parse dst addr
					addrReader := bytes.NewReader(ev.data)
					dstAddr, dstPort, err := parseSocksAddr(addrReader)
					if err != nil {
						return errors.Wrap(err, "parse socks addr")
					}
					if addrReader.Len() != 0 {
						return fmt.Errorf("trailing bytes after parse addr: %v", ev.data)
					}

					// create target
					t := l.targetNew(ctx, ev.cid)
					go t.targetInitializer(ctx, ev.cmd, dstAddr, dstPort)

					return nil
				}()

				// error
				if err != nil {
					ctxlog.Errorf(ctx, "[cid:%v] cmd connect: %v", ev.cid, err)
					l.writerExit <- protoMsg{cmd: kLocalClose}
					return
				}
			case kClientInputUp, kClientInputUpEOF:
				// get target
				t := l.targetGet(ev.cid)
				if t == nil {
					ctxlog.Warnf(ctx, "[cid:%v] not exists", ev.cid)
					continue
				}

				// FIXME: block on closed target?
				// TODO: timeout or flow ctrl
				t.writerInput <- protoMsg{cmd: ev.cmd, data: ev.data}
			case kClientClose:
				t := l.targetGet(ev.cid)
				if t == nil {
					ctxlog.Warnf(ctx, "[cid:%v] not exists", ev.cid)
					continue
				}

				t.writerExit <- protoMsg{cmd: ev.cmd}
				t.readerExit <- protoMsg{cmd: ev.cmd}
			default:
				ctxlog.Errorf(ctx, "[cid:%v] unknown [cmd:%v]", ev.cid, ev.cmd)
			}
		case ev := <-l.readerExit:
			if ev.cmd != kLocalClose {
				panic("bad msg type")
			}
			ctxlog.Infof(ctx, "local reader exit with kRemoteClose")
			return
		} // select
	} // for
}

func (l *localState) localNotifyDequeue(ctx context.Context) *targetState {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.ttail == nil {
		return nil
	}

	t := l.thead
	if t != nil {
		t.notified = false
		l.thead = t.tnext
	}
	if l.thead == nil {
		l.ttail = nil
	}
	return t
}

func (l *localState) localNotifyConsume(ctx context.Context, t *targetState) error {
	// dequeue one event
	t.mu.Lock()
	msg := t.phead
	if msg != nil {
		t.phead = msg.next
		if t.phead == nil {
			t.ptail = nil
		}
		// update ack to remote
		msg.ack = t.fc.rcv
	}
	t.mu.Unlock()

	if msg == nil {
		ctxlog.Debugf(ctx, "[cid:%v] target wake up without event", t.id)
		return nil
	}

	// check msg
	switch msg.cmd {
	case kClientClose, kRemoteInputDownEOF:
	case kRemoteInputDown:
		if len(msg.data) > kMsgRecvMaxLen {
			panic("ensure this")
		}
	default:
		panic("bad msg type")
	}

	// do write io
	if err := msg.writeTo(l.conn); err != nil {
		return err
	}

	// requeue t if t has more event
	t.mu.Lock()
	if t.phead != nil {
		t.localNotify(true)
	}
	t.mu.Unlock()

	return nil
}

func (l *localState) localWriter(ctx context.Context) {
	defer close(l.writerDone)

	for {
		select {
		case <-l.writerNotify:
			for {
				t := l.localNotifyDequeue(ctx)
				if t == nil {
					ctxlog.Debugf(ctx, "local writer has consumed all events")
					break
				}

				if err := l.localNotifyConsume(ctx, t); err != nil {
					ctxlog.Errorf(ctx, "local writer exit with io error: %v", err)
					l.readerExit <- protoMsg{cmd: kLocalClose}
					return
				}
			}
		case ev := <-l.writerExit:
			if ev.cmd != kLocalClose {
				panic("bad msg type")
			}
			ctxlog.Infof(ctx, "local writer exit with kRemoteClose")
			return
		} // select
	} // for
}

func (l *localState) localClose(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// set quiting flag
	l.quiting = true

	// notify all target to quit
	msg := protoMsg{cmd: kClientClose}
	for _, t := range l.targetStates {
		t.readerExit <- msg
		t.writerExit <- msg
	}
}

func (l *localState) targetNew(ctx context.Context, cid uint32) *targetState {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.quiting {
		ctxlog.Warnf(ctx, "can not create target: local is quiting")
		return nil
	}

	if l.targetStates[cid] != nil {
		ctxlog.Errorf(ctx, "[LOCAL_BUG] [cid:%v] exists", cid)
		return nil
	}

	t := &targetState{
		id:    cid,
		local: l,
		// reader
		readerExit: make(chan protoMsg, 4),
		readerDone: make(chan struct{}),
		// writer
		writerInput: make(chan protoMsg, kChannelSize),
		writerExit:  make(chan protoMsg, 4),
		writerDone:  make(chan struct{}),
	}
	t.cond.L = &t.mu
	// TODO: config
	t.fc.win = 1024 * 1024
	l.targetStates[cid] = t
	return l.targetStates[cid]
}

func isIPv6(dstAddr socksAddr) bool {
	switch dstAddr.atype {
	case kSocksAddrIPV4:
		return false
	case kSocksAddrIPV6:
		return true
	case kSocksAddrDomain:
		// firefox bug, ipv6 is domain addr
		return strings.ContainsRune(string(dstAddr.addr), ':')
		//ip := net.ParseIP(string(dstAddr.addr))
		//return ip != nil && ip.To4() == nil
	default:
		panic("bad atype")
	}
}

func socksAddrString(dstAddr socksAddr, dstPort uint16) string {
	if isIPv6(dstAddr) {
		return fmt.Sprintf("[%s]:%d", dstAddr, dstPort)
	} else {
		return fmt.Sprintf("%s:%d", dstAddr, dstPort)
	}
}

func dial(ctx context.Context, addr string, preferV4 bool) (conn net.Conn, err error) {
	d := &net.Dialer{Timeout: 2 * time.Second} // TODO: config
	nets := []string{"tcp"}
	if preferV4 {
		nets = []string{"tcp4", "tcp"}
	}
	for _, network := range nets {
		if conn, err = d.DialContext(ctx, network, addr); err == nil {
			return
		}
		if len(nets) > 1 {
			ctxlog.Debugf(ctx, "try dial %s: %v", network, err)
		}
	}
	return
}

func (t *targetState) targetInitializer(
	ctx context.Context, cmd uint32, dstAddr socksAddr, dstPort uint16) {

	defer t.targetClose(ctx)

	addr := socksAddrString(dstAddr, dstPort)

	// metric
	t.metric.Id = t.id
	t.metric.Target = addr
	t.metric.Created = time.Now().UnixNano() / 1000

	// dial
	ctx = ctxlog.Pushf(ctx, "[cid:%v][target:%s]", t.id, addr)
	conn, err := dial(ctx, addr, t.local.r.PreferIPv4)
	if err != nil {
		ctxlog.Errorf(ctx, "target dial: %v", err)
		t.localWriterEnqueue(ctx, &protoMsg{cmd: kClientClose, cid: t.id})
		return
	}
	t.metric.Connected = time.Now().UnixNano() / 1000
	defer safeClose(ctx, conn)

	// tls
	if cmd == kClientInputConnectSSL {
		if dstAddr.atype != kSocksAddrDomain {
			ctxlog.Errorf(ctx, "[LOCAL_BUG] kClientInputConnectSSL requires ServerName")
			t.localWriterEnqueue(ctx, &protoMsg{cmd: kClientClose, cid: t.id})
			return
		}
		conn = tls.Client(conn, &tls.Config{ServerName: string(dstAddr.addr)})
		// NOTE: will not call tls.Conn.Close
	}

	// connected
	ctxlog.Infof(ctx, "target connected")
	t.conn = conn

	// start target io
	go t.targetReader(ctx)
	go t.targetWriter(ctx)

	// wait for target done
	<-t.readerDone
	<-t.writerDone
	ctxlog.Infof(ctx, "target done")
}

func (t *targetState) targetUpdateAck(ack uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if ack != t.fc.ack && ack-t.fc.ack < 1<<16 {
		prevState := t.fc.state()
		t.fc.ack = ack
		if prevState == kFlowPause {
			t.cond.Signal()
		}
	}
}

func (t *targetState) localWriterEnqueue(ctx context.Context, proto *protoMsg) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if proto.cmd == kRemoteInputDown && t.fc.state() == kFlowPause {
		panic("???")
	}

	// enqueue
	if t.phead == nil {
		t.phead = proto
	} else {
		t.ptail.next = proto
	}
	t.ptail = proto

	// update state
	t.fc.snt += uint32(len(proto.data))

	// notify remote writer
	t.localNotify(false)

	// block on kFlowPause
	for t.fc.state() == kFlowPause {
		ctxlog.Debugf(ctx, "target paused [snt:%v][ack:%v] [inflight:%v] > [window:%v]",
			t.fc.snt, t.fc.ack, t.fc.snt-t.fc.ack, t.fc.win)
		t.cond.Wait()
	}
}

func (t *targetState) localNotify(nosig bool) {
	l := t.local
	l.mu.Lock()
	defer l.mu.Unlock()

	if t.notified {
		return
	}

	if l.thead == nil {
		l.thead = t
	} else {
		l.ttail.tnext = t
	}
	l.ttail = t

	t.notified = true

	if !nosig {
		select {
		case l.writerNotify <- struct{}{}:
		default:
		}
	}
}

func (t *targetState) targetReader(ctx context.Context) {
	defer close(t.readerDone)

	ioInput, ioQuit := reader2chan(t.conn)
	defer close(ioQuit)
	for {
		select {
		case ev := <-ioInput:
			// eof
			if ev == nil {
				t.localWriterEnqueue(ctx, &protoMsg{cmd: kRemoteInputDownEOF, cid: t.id})
				ctxlog.Infof(ctx, "target reader exit with EOF")
				return
			}
			// io error
			if err, ok := ev.(error); ok {
				ctxlog.Errorf(ctx, "target reader exit with error: %v", err)
				msg := &protoMsg{cmd: kClientClose, cid: t.id}
				t.localWriterEnqueue(ctx, msg)
				t.writerExit <- *msg
				return
			}

			data := ev.([]byte)
			if len(data) > kMsgRecvMaxLen {
				panic("ensure this")
			}

			// metric
			if t.metric.FirstRead == 0 {
				t.metric.FirstRead = time.Now().UnixNano() / 1000
			}
			t.metric.LastRead = time.Now().UnixNano() / 1000
			t.metric.BytesRead += len(data)

			// send data to local
			ctxlog.Debugf(ctx, "target reader got %v bytes", len(data))
			t.localWriterEnqueue(ctx, &protoMsg{cmd: kRemoteInputDown, cid: t.id, data: data})
		case ev := <-t.readerExit:
			if ev.cmd != kClientClose {
				panic("bad msg type")
			}
			ctxlog.Infof(ctx, "target reader exit with kClientClose")
			return
		} // select
	} // for
}

func (t *targetState) targetWriter(ctx context.Context) {
	defer close(t.writerDone)

	for {
		select {
		case ev := <-t.writerInput:
			// do io
			var err error
			switch ev.cmd {
			case kClientInputUp:
				ctxlog.Debugf(ctx, "target writer got %v bytes", len(ev.data))
				if t.metric.FirstWrite == 0 {
					t.metric.FirstWrite = time.Now().UnixNano() / 1000
				}
				t.metric.BytesWritten += len(ev.data)

				_, err = t.conn.Write(ev.data)
			case kClientInputUpEOF:
				err = t.conn.(interface{ CloseWrite() error }).CloseWrite() // assume tcp
			default:
				panic("bad msg type")
			}

			if err != nil {
				ctxlog.Errorf(ctx, "target writer exit with io error: %v", err)
				msg := &protoMsg{cmd: kClientClose, cid: t.id}
				t.readerExit <- *msg
				t.localWriterEnqueue(ctx, msg)
				return
			}

			if ev.cmd == kClientInputUpEOF {
				ctxlog.Infof(ctx, "target writer exit with EOF")
				return
			}

			if len(ev.data) > 0 {
				needAck := false
				ack := uint32(0)
				t.mu.Lock()
				// update t.rcv
				t.fc.rcv += uint32(len(ev.data))
				ack = t.fc.rcv
				// send empty data packet to ack local
				if t.phead == nil {
					// NOTE: can't call t.localWriterEnqueue() since we can't block on here
					needAck = true
					msg := &protoMsg{cmd: kRemoteInputDown, cid: t.id, data: nil}
					t.phead = msg
					t.ptail = msg
					t.localNotify(false)
				}
				t.mu.Unlock()
				ctxlog.Debugf(ctx, "target writer [need_ack:%v][ack:%v]", needAck, ack)
			}
		case ev := <-t.writerExit:
			if ev.cmd != kClientClose {
				panic("bad msg type")
			}
			ctxlog.Infof(ctx, "target writer exit with kClientClose")
			return
		} // select
	} // for
}

func (t *targetState) targetClose(ctx context.Context) {
	// metric
	t.metric.Closed = time.Now().UnixNano() / 1000
	if metric, err := json.Marshal(t.metric); err == nil {
		ctxlog.Debugf(context.Background(), "METRIC %s", string(metric))
	}

	// erase from remote map
	t.local.mu.Lock()
	defer t.local.mu.Unlock()
	delete(t.local.targetStates, t.id)

	if len(t.local.targetStates) == 0 {
		ctxlog.Debugf(ctx, "i am the last target")
	}
}

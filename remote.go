package ssloff

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/account-login/ctxlog"
	"github.com/pkg/errors"
	"io"
	"net"
	"sync"
)

type Remote struct {
	// param
	RemoteAddr string
}

type localState struct {
	conn net.Conn
	// reader
	readerExit chan protoMsg
	readerDone chan struct{}
	// writer
	writerInput chan protoMsg
	writerExit  chan protoMsg
	writerDone  chan struct{}
	// targets
	mu           sync.Mutex
	targetStates map[uint32]*targetState
	quiting      bool
}

type targetState struct {
	id    uint32
	conn  net.Conn
	local *localState
	// reader
	readerExit chan protoMsg
	readerDone chan struct{}
	// writer
	writerInput chan protoMsg
	writerExit  chan protoMsg
	writerDone  chan struct{}
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
		conn:         conn,
		readerExit:   make(chan protoMsg, 4),
		readerDone:   make(chan struct{}),
		writerInput:  make(chan protoMsg, kChannelSize),
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

			ctxlog.Debugf(ctx, "[cid:%v][cmd:%v][data_len:%v]", ev.cid, ev.cmd, len(ev.data))

			switch ev.cmd {
			case kClientInputConnect:
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
					l.mu.Lock()
					defer l.mu.Unlock()

					if l.quiting {
						return fmt.Errorf("local is quiting")
					}

					if l.targetStates[ev.cid] != nil {
						return fmt.Errorf("[CLIENT_BUG] [cid:%v] exists", ev.cid)
					}

					l.targetStates[ev.cid] = &targetState{
						id:    ev.cid,
						local: l,
						// reader
						readerExit: make(chan protoMsg, 4),
						readerDone: make(chan struct{}),
						// writer
						writerInput: make(chan protoMsg, kChannelSize),
						writerExit:  make(chan protoMsg, 4),
						writerDone:  make(chan struct{}),
					}

					go l.targetStates[ev.cid].targetInitializer(ctx, dstAddr, dstPort)

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

func (l *localState) localWriter(ctx context.Context) {
	defer close(l.writerDone)

	for {
		select {
		case ev := <-l.writerInput:
			var msg protoMsg
			switch ev.cmd {
			case kRemoteInputDown:
				if len(ev.data) > kMsgRecvMaxLen {
					panic("ensure this")
				}
				msg = protoMsg{cmd: ev.cmd, cid: ev.cid, data: ev.data}
			case kRemoteInputDownEOF:
				msg = protoMsg{cmd: ev.cmd, cid: ev.cid}
			case kClientClose:
				msg = protoMsg{cmd: ev.cmd, cid: ev.cid}
			default:
				panic("bad msg type")
			}

			if err := msg.writeTo(l.conn); err != nil {
				ctxlog.Errorf(ctx, "local writer exit with io error: %v", err)
				l.readerExit <- protoMsg{cmd: kLocalClose}
				return
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

func (t *targetState) targetInitializer(ctx context.Context, dstAddr socksAddr, dstPort uint16) {
	// dial
	addrStr := fmt.Sprintf("%s:%d", dstAddr, dstPort)
	ctx = ctxlog.Pushf(ctx, "[cid:%v][target:%s]", t.id, addrStr)
	conn, err := net.Dial("tcp", addrStr)
	if err != nil {
		ctxlog.Errorf(ctx, "target dial: %v", err)
		t.local.writerInput <- protoMsg{cmd: kClientClose, cid: t.id}
		return
	}

	// connected
	defer safeClose(ctx, conn)
	ctxlog.Infof(ctx, "target connected")
	t.conn = conn

	// start target io
	go t.targetReader(ctx)
	go t.targetWriter(ctx)

	// wait for target done
	<-t.readerDone
	<-t.writerDone

	// clear target state
	t.targetClose(ctx)
	ctxlog.Infof(ctx, "target done")
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
				t.local.writerInput <- protoMsg{cmd: kRemoteInputDownEOF, cid: t.id}
				ctxlog.Infof(ctx, "target reader exit with EOF")
				return
			}
			// io error
			if err, ok := ev.(error); ok {
				ctxlog.Errorf(ctx, "target reader exit with error: %v", err)
				t.local.writerInput <- protoMsg{cmd: kClientClose, cid: t.id}
				t.writerExit <- protoMsg{cmd: kClientClose, cid: t.id}
				return
			}

			// send data to local
			data := ev.([]byte)
			if len(data) > kMsgRecvMaxLen {
				panic("ensure this")
			}
			ctxlog.Debugf(ctx, "target reader got %v bytes", len(data))
			t.local.writerInput <- protoMsg{cmd: kRemoteInputDown, cid: t.id, data: data}
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
				_, err = t.conn.Write(ev.data)
			case kClientInputUpEOF:
				err = t.conn.(interface{ CloseWrite() error }).CloseWrite() // assume tcp
			default:
				panic("bad msg type")
			}

			if err != nil {
				ctxlog.Errorf(ctx, "target writer exit with io error: %v", err)
				t.readerExit <- protoMsg{cmd: kClientClose, cid: t.id}
				t.local.writerInput <- protoMsg{cmd: kClientClose, cid: t.id}
				return
			}

			if ev.cmd == kClientInputUpEOF {
				ctxlog.Infof(ctx, "target writer exit with EOF")
				return
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
	// erase from remote map
	t.local.mu.Lock()
	defer t.local.mu.Unlock()
	delete(t.local.targetStates, t.id)

	if len(t.local.targetStates) == 0 {
		ctxlog.Debugf(ctx, "i am the last target")
	}
}

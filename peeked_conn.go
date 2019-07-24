package ssloff

import (
	"net"
	"time"
)

type peekedConn struct {
	peeked []byte
	conn   net.Conn
}

func (conn *peekedConn) Read(b []byte) (n int, err error) {
	if len(conn.peeked) > 0 {
		n = len(b)
		if n > len(conn.peeked) {
			n = len(conn.peeked)
		}

		copy(b, conn.peeked[:n])
		conn.peeked = conn.peeked[n:]
		if len(conn.peeked) == 0 {
			conn.peeked = nil // release underlying array
		}
		return
	}

	return conn.conn.Read(b)
}

func (conn *peekedConn) Write(b []byte) (n int, err error) {
	return conn.conn.Write(b)
}

func (conn *peekedConn) Close() error {
	return conn.conn.Close()
}

func (conn *peekedConn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

func (conn *peekedConn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

func (conn *peekedConn) SetDeadline(t time.Time) error {
	return conn.conn.SetDeadline(t)
}

func (conn *peekedConn) SetReadDeadline(t time.Time) error {
	return conn.conn.SetReadDeadline(t)
}

func (conn *peekedConn) SetWriteDeadline(t time.Time) error {
	return conn.conn.SetWriteDeadline(t)
}

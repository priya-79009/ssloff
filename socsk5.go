package ssloff

import (
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"net"
)

type socksAddr struct {
	atype uint8
	addr  []byte
}

func (sa socksAddr) String() string {
	switch sa.atype {
	case 1, 4:
		return net.IP(sa.addr).String()
	case 3:
		return string(sa.addr)
	default:
		panic("bad atype")
	}
}

func serializeSocksAddr(sa socksAddr, port uint16) (buf []byte) {
	switch sa.atype {
	case 1:
		if len(sa.addr) != 4 {
			panic("bad socksAddr")
		}
		buf = make([]byte, 1+4+2)
	case 4:
		if len(sa.addr) != 16 {
			panic("bad socksAddr")
		}
		buf = make([]byte, 1+16+2)
	case 3:
		if len(sa.addr) > 256 {
			panic("bad socksAddr")
		}
		buf = make([]byte, 1+1+len(sa.addr)+2)
		buf[1] = byte(len(sa.addr))
	default:
		panic("bad atype")
	}

	buf[0] = sa.atype
	copy(buf[len(buf)-2-len(sa.addr):len(buf)-2], sa.addr)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], port)
	return
}

func parseSocksAddr(reader io.Reader) (sa socksAddr, port uint16, err error) {
	var atype [1]byte
	if _, err = io.ReadFull(reader, atype[:]); err != nil {
		return
	}

	// addr
	sa.atype = atype[0]
	switch sa.atype {
	case 1:
		sa.addr = make([]byte, 4)
	case 4:
		sa.addr = make([]byte, 16)
	case 3:
		var alen [1]byte
		_, err = io.ReadFull(reader, alen[:])
		if err != nil {
			err = errors.Wrap(err, "socks5 read alen")
			return
		}
		sa.addr = make([]byte, alen[0])
	default:
		err = fmt.Errorf("bad [atype:%v]", sa.atype)
		return
	}
	_, err = io.ReadFull(reader, sa.addr)
	if err != nil {
		err = errors.Wrap(err, "socks5 read abody")
		return
	}

	// port
	var addrPort [2]byte
	_, err = io.ReadFull(reader, addrPort[:])
	if err != nil {
		err = errors.Wrap(err, "socks5 read dst port")
		return
	}
	port = binary.BigEndian.Uint16(addrPort[:])

	return
}

func socks5handshake(conn io.ReadWriter) (
	dstAddr socksAddr, dstPort uint16, err error) {
	// auth
	var h2 [2]byte
	_, err = io.ReadFull(conn, h2[:])
	if err != nil {
		err = errors.Wrap(err, "socks5 read method num")
		return
	}
	if h2[0] != 5 {
		err = fmt.Errorf("socks5 [ver:%v] != 5", h2[0])
		return
	}
	_, err = io.ReadFull(conn, make([]byte, h2[1]))
	if err != nil {
		err = errors.Wrap(err, "socks5 read methods")
		return
	}

	// reply auth
	_, err = conn.Write([]byte{5, 0})
	if err != nil {
		err = errors.Wrap(err, "socks5 write method")
		return
	}

	// req
	var h3 [3]byte
	_, err = io.ReadFull(conn, h3[:])
	if err != nil {
		err = errors.Wrap(err, "socks5 read h3")
		return
	}
	if h3[0] != 5 || h3[1] != 1 {
		err = fmt.Errorf("socks5 [ver:%v][cmd:%v] != 5, 1", h3[0], h3[1])
		return
	}

	// dst addr, dst port
	if dstAddr, dstPort, err = parseSocksAddr(conn); err != nil {
		return
	}

	// reply connect req
	_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		err = errors.Wrap(err, "socks5 write reply")
		return
	}

	return
}

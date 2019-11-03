package ssloff

import (
	"bytes"
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

const (
	kSocksAddrIPV4   = 1
	kSocksAddrIPV6   = 4
	kSocksAddrDomain = 3
)

func (sa socksAddr) String() string {
	switch sa.atype {
	case kSocksAddrIPV4, kSocksAddrIPV6:
		return net.IP(sa.addr).String()
	case kSocksAddrDomain:
		return string(sa.addr)
	default:
		panic("bad atype")
	}
}

func serializeSocksAddr(sa socksAddr, port uint16) (buf []byte) {
	switch sa.atype {
	case kSocksAddrIPV4:
		if len(sa.addr) != 4 {
			panic("bad socksAddr")
		}
		buf = make([]byte, 1+4+2)
	case kSocksAddrIPV6:
		if len(sa.addr) != 16 {
			panic("bad socksAddr")
		}
		buf = make([]byte, 1+16+2)
	case kSocksAddrDomain:
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

func socksAddrString(dstAddr socksAddr, dstPort uint16) string {
	if isIPv6(dstAddr) {
		return fmt.Sprintf("[%s]:%d", dstAddr, dstPort)
	} else {
		return fmt.Sprintf("%s:%d", dstAddr, dstPort)
	}
}

func parseSocksAddrData(data []byte) (sa socksAddr, port uint16, err error) {
	addrReader := bytes.NewReader(data)
	sa, port, err = parseSocksAddr(addrReader)
	if err != nil {
		return
	}
	if addrReader.Len() != 0 {
		err = fmt.Errorf("trailing bytes after parse addr: %v", data)
	}
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
	case kSocksAddrIPV4:
		sa.addr = make([]byte, 4)
	case kSocksAddrIPV6:
		sa.addr = make([]byte, 16)
	case kSocksAddrDomain:
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

const kSocks4IdMax = 255

func socks4readid(conn io.ReadWriter) (id string, err error) {
	var b [1]byte
	for i := 0; i <= kSocks4IdMax; i++ {
		if _, err = io.ReadFull(conn, b[:]); err != nil {
			err = errors.Wrapf(err, "socks4 read id")
			return
		}

		if b[0] == 0 {
			return
		}
		id += string(b[:])
	}

	err = errors.New("socks4 id too long")
	return
}

func socks4sub(conn io.ReadWriter) (dstAddr socksAddr, dstPort uint16, err error) {
	var a6 [6]byte
	if _, err = io.ReadFull(conn, a6[:]); err != nil {
		err = errors.Wrapf(err, "socks4 read req")
		return
	}

	// port
	dstPort = binary.BigEndian.Uint16(a6[:2])

	// user id
	if _, err = socks4readid(conn); err != nil {
		return
	}

	if a6[2] == 0 && a6[3] == 0 && a6[4] == 0 {
		// socks4a
		var domain string
		if domain, err = socks4readid(conn); err != nil {
			return
		}

		dstAddr.atype = kSocksAddrDomain
		dstAddr.addr = []byte(domain)
	} else {
		dstAddr.atype = kSocksAddrIPV4
		dstAddr.addr = make([]byte, 4)
		copy(dstAddr.addr, a6[2:6])
	}

	// reply
	if _, err = conn.Write([]byte{0, 0x5a, 1, 2, 1, 2, 3, 4}); err != nil {
		err = errors.Wrap(err, "socks4 write reply")
		return
	}

	return
}

func socks5handshake(conn io.ReadWriter) (dstAddr socksAddr, dstPort uint16, err error) {
	// auth or socks4 header
	var h2 [2]byte
	if _, err = io.ReadFull(conn, h2[:]); err != nil {
		err = errors.Wrap(err, "socks5 read method num")
		return
	}

	// detect socks4
	if h2[0] == 4 && h2[1] == 1 {
		return socks4sub(conn)
	}

	if h2[0] != 5 {
		err = fmt.Errorf("socks5 [ver:%v] != 5", h2[0])
		return
	}
	if _, err = io.ReadFull(conn, make([]byte, h2[1])); err != nil {
		err = errors.Wrap(err, "socks5 read methods")
		return
	}

	// reply auth
	if _, err = conn.Write([]byte{5, 0}); err != nil {
		err = errors.Wrap(err, "socks5 write method")
		return
	}

	// req
	var h3 [3]byte
	if _, err = io.ReadFull(conn, h3[:]); err != nil {
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
	if _, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		err = errors.Wrap(err, "socks5 write reply")
		return
	}

	return
}

package ssloff

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/account-login/ssloff/mitm"
	"io"
	"io/ioutil"
	"net"
	"os"
	"time"
)

type fakeNetConn struct {
	buf []byte
}

func (conn *fakeNetConn) Read(b []byte) (n int, err error) {
	if len(conn.buf) == 0 {
		return 0, io.EOF
	}
	n = len(b)
	if n > len(conn.buf) {
		n = len(conn.buf)
	}
	copy(b, conn.buf[:n])
	conn.buf = conn.buf[n:]
	return
}

func (conn *fakeNetConn) Write(b []byte) (n int, err error) {
	n = len(b)
	return
}

func (conn *fakeNetConn) Close() error {
	return nil
}

func (conn *fakeNetConn) LocalAddr() net.Addr {
	return nil
}

func (conn *fakeNetConn) RemoteAddr() net.Addr {
	return nil
}

func (conn *fakeNetConn) SetDeadline(t time.Time) error {
	return nil
}

func (conn *fakeNetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (conn *fakeNetConn) SetWriteDeadline(t time.Time) error {
	return nil
}

var dummyError = errors.New("haha")

func detectTLS(input []byte) (name string, ok bool) {
	c := tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName != "" {
				name = clientHello.ServerName
				ok = true
			}
			return nil, dummyError
		},
	}

	bufconn := fakeNetConn{buf: input}
	tlsconn := tls.Server(&bufconn, &c)
	_ = tlsconn.Handshake()

	return
}

type MITM struct {
	*mitm.Config

	CAPath   string
	CacheDir string
}

func (m *MITM) Init() error {
	// create CA if not exists
	if _, err := os.Stat(m.CAPath); os.IsNotExist(err) {
		validity := 20 * 365 * 24 * time.Hour
		cert, privkey, err := mitm.NewAuthority("ssloff", "ssloff", validity)
		if err != nil {
			return err
		}

		certData := pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: cert.Raw,
		})
		keyData := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privkey),
		})

		merged := append(certData, keyData...)
		if err = ioutil.WriteFile(m.CAPath, merged, 0600); err != nil {
			return err
		}
	}

	// load CA
	data, err := ioutil.ReadFile(m.CAPath)
	if err != nil {
		return err
	}
	pemMap := map[string][]byte{}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		pemMap[block.Type] = block.Bytes
	}

	cert, err := x509.ParseCertificate(pemMap["CERTIFICATE"])
	if err != nil {
		return err
	}
	privkey, err := x509.ParsePKCS1PrivateKey(pemMap["RSA PRIVATE KEY"])
	if err != nil {
		return err
	}

	m.Config, err = mitm.NewConfig(cert, privkey)
	if err != nil {
		return err
	}

	return nil
}

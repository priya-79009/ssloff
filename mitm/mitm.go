// Copyright 2015 Google Inc. All rights reserved.
// Modified by xxx.
// From github.com/google/martian/mitm/mitm.go
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package mitm provides tooling for MITMing TLS connections. It provides
// tooling to create CA certs and generate TLS configs that can be used to MITM
// a TLS connection with a provided CA certificate.
package mitm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/account-login/ctxlog"
)

// MaxSerialNumber is the upper boundary that is used to create unique serial
// numbers for the certificate. This can be any unsigned integer up to 20
// bytes (2^(8*20)-1).
var MaxSerialNumber = big.NewInt(0).SetBytes(bytes.Repeat([]byte{255}, 20))

// Config is a set of configuration values that are used to build TLS configs
// capable of MITM.
type Config struct {
	ca                     *x509.Certificate
	capriv                 interface{}
	priv                   *rsa.PrivateKey
	keyID                  []byte
	validity               time.Duration
	org                    string
	getCertificate         func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	roots                  *x509.CertPool
	skipVerify             bool
	handshakeErrorCallback func(*http.Request, error)
	cacheDir               string

	certmu sync.RWMutex
	certs  map[string]*tls.Certificate
}

// NewAuthority creates a new CA certificate and associated
// private key.
func NewAuthority(name, organization string, validity time.Duration) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	// TODO: keep a map of used serial numbers to avoid potentially reusing a
	// serial multiple times.
	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{organization},
		},
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-validity),
		NotAfter:              time.Now().Add(validity),
		DNSNames:              []string{name},
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return x509c, priv, nil
}

// NewConfig creates a MITM config using the CA certificate and
// private key to generate on-the-fly certificates.
func NewConfig(ca *x509.Certificate, privateKey interface{}) (*Config, error) {
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	//priv, err := rsa.GenerateKey(rand.Reader, 2048)
	//if err != nil {
	//	return nil, err
	//}
	priv := privateKey.(*rsa.PrivateKey) // (ab)use ca key for cert key
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	return &Config{
		ca:       ca,
		capriv:   privateKey,
		priv:     priv,
		keyID:    keyID,
		validity: 20 * 365 * 24 * time.Hour,
		org:      "ssloff",
		certs:    make(map[string]*tls.Certificate),
		roots:    roots,
	}, nil
}

func (c *Config) SetCacheDir(dir string) {
	c.cacheDir = dir
}

// SetValidity sets the validity window around the current time that the
// certificate is valid for.
func (c *Config) SetValidity(validity time.Duration) {
	c.validity = validity
}

// SkipTLSVerify skips the TLS certification verification check.
func (c *Config) SkipTLSVerify(skip bool) {
	c.skipVerify = skip
}

// SetOrganization sets the organization of the certificate.
func (c *Config) SetOrganization(org string) {
	c.org = org
}

// SetHandshakeErrorCallback sets the handshakeErrorCallback function.
func (c *Config) SetHandshakeErrorCallback(cb func(*http.Request, error)) {
	c.handshakeErrorCallback = cb
}

// HandshakeErrorCallback calls the handshakeErrorCallback function in this
// Config, if it is non-nil. Request is the connect request that this handshake
// is being executed through.
func (c *Config) HandshakeErrorCallback(r *http.Request, err error) {
	if c.handshakeErrorCallback != nil {
		c.handshakeErrorCallback(r, err)
	}
}

// TLS returns a *tls.Config that will generate certificates on-the-fly using
// the SNI extension in the TLS ClientHello.
func (c *Config) TLS(ctx context.Context) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: c.skipVerify,
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName == "" {
				return nil, errors.New("mitm: SNI not provided, failed to build certificate")
			}

			return c.cert(ctx, clientHello.ServerName)
		},
		NextProtos: []string{"http/1.1"},
	}
}

// TLSForHost returns a *tls.Config that will generate certificates on-the-fly
// using SNI from the connection, or fall back to the provided hostname.
func (c *Config) TLSForHost(ctx context.Context, hostname string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: c.skipVerify,
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := clientHello.ServerName
			if host == "" {
				host = hostname
			}

			return c.cert(ctx, host)
		},
		NextProtos: []string{"http/1.1"},
	}
}

func hostWildBase(host string) string {
	tld, icann := publicsuffix.PublicSuffix(host)
	if !icann {
		return ""
	}

	headBody := host[0 : len(host)-len(tld)-1]
	if i := strings.IndexByte(headBody, '.'); i > 0 {
		return host[i+1:]
	}

	return ""
}

func (c *Config) certFromCache(
	ctx context.Context, key string, subjectName string) (*tls.Certificate, error) {

	// memory
	c.certmu.RLock()
	tlsc := c.certs[key]
	c.certmu.RUnlock()
	if tlsc != nil {
		return tlsc, nil
	}

	// file
	if c.cacheDir == "" {
		return nil, errors.New("cache not enabled")
	}
	filePath := path.Join(c.cacheDir, key)

	// read file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// decode cert
	block, _ := pem.Decode(data)
	if block == nil {
		ctxlog.Errorf(ctx, "can not decode pem")
		return nil, errors.New("can not decode pem")
	}

	x509c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		ctxlog.Errorf(ctx, "parse cert: %v", err)
		return nil, err
	}

	tlsc = &tls.Certificate{
		Certificate: [][]byte{x509c.Raw, c.ca.Raw},
		PrivateKey:  c.priv,
		Leaf:        x509c,
	}

	// hit
	ctxlog.Debugf(ctx, "hit from file: %s", filePath)
	c.certmu.Lock()
	c.certs[key] = tlsc
	c.certmu.Unlock()
	return tlsc, nil
}

func (c *Config) certToCache(ctx context.Context, key string, tlsc *tls.Certificate) error {
	// memory
	c.certmu.Lock()
	c.certs[key] = tlsc
	c.certmu.Unlock()

	// file
	if c.cacheDir == "" {
		return nil // no file cache
	}
	filePath := path.Join(c.cacheDir, key)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: tlsc.Leaf.Raw,
	})
	if err := ioutil.WriteFile(filePath, pemData, 0644); err != nil {
		ctxlog.Errorf(ctx, "write file %s: %v", filePath, err)
		return err
	}

	// ok
	return nil
}

func (c *Config) cert(ctx context.Context, hostname string) (*tls.Certificate, error) {
	// Remove the port if it exists.
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}

	// wildcard
	subjectName := hostname
	key := hostname
	if wildBase := hostWildBase(hostname); wildBase != "" {
		subjectName = "*." + wildBase
		key = subjectName[1:]
	}

	tlsc, err := c.certFromCache(ctx, key, subjectName)
	if err == nil {
		ctxlog.Debugf(ctx, "mitm: cache hit for %s", hostname)

		// Check validity of the certificate for hostname match, expiry, etc. In
		// particular, if the cached certificate has expired, create a new one.
		if _, err := tlsc.Leaf.Verify(x509.VerifyOptions{
			DNSName: hostname,
			Roots:   c.roots,
		}); err == nil {
			return tlsc, nil
		}

		ctxlog.Debugf(ctx, "mitm: invalid certificate in cache for %s", hostname)
	}

	ctxlog.Debugf(ctx, "mitm: cache miss for %s", hostname)
	if tlsc, err = c.generateCert(ctx, subjectName); err != nil {
		return nil, err
	}
	_ = c.certToCache(ctx, key, tlsc)

	return tlsc, nil
}

func (c *Config) generateCert(ctx context.Context, subjectName string) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   subjectName,
			Organization: []string{c.org},
		},
		SubjectKeyId:          c.keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-c.validity),
		NotAfter:              time.Now().Add(c.validity),
	}

	if ip := net.ParseIP(subjectName); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{subjectName}
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, c.priv.Public(), c.capriv)
	if err != nil {
		return nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	tlsc := &tls.Certificate{
		Certificate: [][]byte{raw, c.ca.Raw},
		PrivateKey:  c.priv,
		Leaf:        x509c,
	}
	return tlsc, nil
}

package fake

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/dela/crypto"
	"go.dedis.ch/dela/mino"
	"go.dedis.ch/dela/serde"
)

// Address is a fake implementation of an address.
//
// - implements mino.Address
type Address struct {
	mino.Address
	index int
	err   error
}

// NewAddress returns a fake address with the given index.
func NewAddress(index int) Address {
	return Address{index: index}
}

// NewBadAddress returns a fake address that returns an error when appropriate.
func NewBadAddress() Address {
	return Address{err: fakeErr}
}

// Equal implements mino.Address.
func (a Address) Equal(o mino.Address) bool {
	other, ok := o.(Address)
	return ok && other.index == a.index
}

// MarshalText implements encoding.TextMarshaler.
func (a Address) MarshalText() ([]byte, error) {
	buffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(buffer, uint32(a.index))
	return buffer, a.err
}

// String implements fmt.Stringer.
func (a Address) String() string {
	return fmt.Sprintf("fake.Address[%d]", a.index)
}

// AddressFactory is a fake implementation of an address factory.
//
// - implements mino.AddressFactory
type AddressFactory struct {
	mino.AddressFactory
}

// FromText implements mino.AddressFactory.
func (f AddressFactory) FromText(text []byte) mino.Address {
	if len(text) >= 4 {
		index := binary.LittleEndian.Uint32(text)
		return Address{index: int(index)}
	}
	return Address{}
}

// AddressIterator is a fake implementation an address iterator.
//
// - implements mino.AddressIterator
type AddressIterator struct {
	mino.AddressIterator
	addrs []mino.Address
	index int
}

// NewAddressIterator returns a new address iterator
func NewAddressIterator(addrs []mino.Address) *AddressIterator {
	return &AddressIterator{
		addrs: addrs,
	}
}

// Seek implements mino.AddressIterator.
func (i *AddressIterator) Seek(index int) {
	i.index = index
}

// HasNext implements mino.AddressIterator.
func (i *AddressIterator) HasNext() bool {
	return i.index < len(i.addrs)
}

// GetNext implements mino.AddressIterator.
func (i *AddressIterator) GetNext() mino.Address {
	res := i.addrs[i.index]
	i.index++
	return res
}

// PublicKeyIterator is a fake implementation of a public key iterator.
//
// - implements crypto.PublicKeyIterator
type PublicKeyIterator struct {
	signers []crypto.Signer
	index   int
}

// NewPublicKeyIterator returns a new address iterator
func NewPublicKeyIterator(signers []crypto.Signer) *PublicKeyIterator {
	return &PublicKeyIterator{
		signers: signers,
	}
}

// Seek implements crypto.PublicKeyIterator.
func (i *PublicKeyIterator) Seek(index int) {
	i.index = index
}

// HasNext implements crypto.PublicKeyIterator.
func (i *PublicKeyIterator) HasNext() bool {
	return i.index < len(i.signers)
}

// GetNext implements crypto.PublicKeyIterator.
func (i *PublicKeyIterator) GetNext() crypto.PublicKey {
	if i.HasNext() {
		res := i.signers[i.index]
		i.index++
		return res.GetPublicKey()
	}
	return nil
}

// CollectiveAuthority is a fake implementation of a collective authority.
//
// - implements crypto.CollectiveAuthority
type CollectiveAuthority struct {
	crypto.CollectiveAuthority
	addrs   []mino.Address
	signers []crypto.Signer

	Call           *Call
	PubkeyNotFound bool
}

// GenSigner is a function to generate a signer.
type GenSigner func() crypto.Signer

// NewAuthority returns a new collective authority of n members with new signers
// generated by g.
func NewAuthority(n int, g GenSigner) CollectiveAuthority {
	return NewAuthorityWithBase(0, n, g)
}

// NewAuthorityWithBase returns a new fake collective authority of size n with
// a given starting base index.
func NewAuthorityWithBase(base int, n int, g GenSigner) CollectiveAuthority {
	signers := make([]crypto.Signer, n)
	for i := range signers {
		signers[i] = g()
	}

	addrs := make([]mino.Address, n)
	for i := range addrs {
		addrs[i] = Address{index: i + base}
	}

	return CollectiveAuthority{
		signers: signers,
		addrs:   addrs,
	}
}

// NewAuthorityFromMino returns a new fake collective authority using
// the addresses of the Mino instances.
func NewAuthorityFromMino(g GenSigner, instances ...mino.Mino) CollectiveAuthority {
	signers := make([]crypto.Signer, len(instances))
	for i := range signers {
		signers[i] = g()
	}

	addrs := make([]mino.Address, len(instances))
	for i, instance := range instances {
		addrs[i] = instance.GetAddress()
	}

	return CollectiveAuthority{
		signers: signers,
		addrs:   addrs,
	}
}

// GetAddress returns the address at the provided index.
func (ca CollectiveAuthority) GetAddress(index int) mino.Address {
	return ca.addrs[index]
}

// GetSigner returns the signer at the provided index.
func (ca CollectiveAuthority) GetSigner(index int) crypto.Signer {
	return ca.signers[index]
}

// GetPublicKey implements crypto.CollectiveAuthority.
func (ca CollectiveAuthority) GetPublicKey(addr mino.Address) (crypto.PublicKey, int) {
	if ca.PubkeyNotFound {
		return nil, -1
	}

	for i, address := range ca.addrs {
		if address.Equal(addr) {
			return ca.signers[i].GetPublicKey(), i
		}
	}
	return nil, -1
}

// Take implements mino.Players.
func (ca CollectiveAuthority) Take(updaters ...mino.FilterUpdater) mino.Players {
	filter := mino.ApplyFilters(updaters)
	newCA := CollectiveAuthority{
		Call:    ca.Call,
		addrs:   make([]mino.Address, len(filter.Indices)),
		signers: make([]crypto.Signer, len(filter.Indices)),
	}
	for i, k := range filter.Indices {
		newCA.addrs[i] = ca.addrs[k]
		newCA.signers[i] = ca.signers[k]
	}
	return newCA
}

// Len implements mino.Players.
func (ca CollectiveAuthority) Len() int {
	return len(ca.signers)
}

// AddressIterator implements mino.Players.
func (ca CollectiveAuthority) AddressIterator() mino.AddressIterator {
	return &AddressIterator{addrs: ca.addrs}
}

// PublicKeyIterator implements crypto.CollectiveAuthority.
func (ca CollectiveAuthority) PublicKeyIterator() crypto.PublicKeyIterator {
	return &PublicKeyIterator{signers: ca.signers}
}

// ReceiverMessage is the combination of an address and a message that is
// returned by the receiver.
type ReceiverMessage struct {
	Address mino.Address
	Message serde.Message
}

// NewRecvMsg creates a new receiver message.
func NewRecvMsg(addr mino.Address, msg serde.Message) ReceiverMessage {
	return ReceiverMessage{
		Address: addr,
		Message: msg,
	}
}

// Receiver is a fake RPC stream receiver. It will return the consecutive
// messages stored in the Msg slice.
//
// - implements mino.Receiver
type Receiver struct {
	mino.Receiver
	err      error
	Msgs     []ReceiverMessage
	index    int
	blocking bool
}

// NewReceiver returns a new receiver
func NewReceiver(msgs ...ReceiverMessage) *Receiver {
	return &Receiver{
		Msgs: msgs,
		err:  io.EOF,
	}
}

// NewBlockingReceiver returns a new fake receiver that is blocking until the
// context is done.
func NewBlockingReceiver() *Receiver {
	return &Receiver{
		blocking: true,
	}
}

// NewBadReceiver returns a new receiver that returns an error.
func NewBadReceiver(msg ...ReceiverMessage) *Receiver {
	return &Receiver{Msgs: msg, err: fakeErr}
}

// Recv implements mino.Receiver.
func (r *Receiver) Recv(ctx context.Context) (mino.Address, serde.Message, error) {
	if r.blocking {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}

	if len(r.Msgs) == 0 {
		return nil, nil, r.err
	}

	// In the case there are no more messages to read we return nil.
	if r.index >= len(r.Msgs) {
		return nil, nil, r.err
	}

	defer func() {
		r.index++
	}()

	m := r.Msgs[r.index]

	return m.Address, m.Message, nil
}

// Sender is a fake RPC stream sender.
//
// - implements mino.Sender
type Sender struct {
	mino.Sender
	err error
}

// NewBadSender returns a sender that always returns an error.
func NewBadSender() Sender {
	return Sender{err: fakeErr}
}

// Send implements mino.Sender.
func (s Sender) Send(serde.Message, ...mino.Address) <-chan error {
	errs := make(chan error, 1)
	if s.err != nil {
		errs <- s.err
	}

	close(errs)
	return errs
}

// RPC is a fake implementation of an RPC.
//
// - implements mino.RPC
type RPC struct {
	mino.RPC
	Calls    *Call
	msgs     chan mino.Response
	receiver *Receiver
	sender   Sender
	err      error
}

// NewRPC returns a fake rpc.
func NewRPC() *RPC {
	rpc := &RPC{}
	rpc.Reset()
	return rpc
}

// NewStreamRPC returns a fake rpc with specific stream options.
func NewStreamRPC(r *Receiver, s Sender) *RPC {
	rpc := &RPC{
		receiver: r,
		sender:   s,
	}
	rpc.Reset()
	return rpc
}

// NewBadRPC returns a fake rpc that returns an error when appropriate.
func NewBadRPC() *RPC {
	rpc := &RPC{
		err: fakeErr,
	}
	rpc.Reset()
	return rpc
}

// SendResponse fills the rpc with a message.
func (rpc *RPC) SendResponse(from mino.Address, msg serde.Message) {
	rpc.msgs <- mino.NewResponse(from, msg)
}

// SendResponseWithError fills the rpc with an error.
func (rpc *RPC) SendResponseWithError(from mino.Address, err error) {
	rpc.msgs <- mino.NewResponseWithError(from, err)
}

// Done closes the response channel.
func (rpc *RPC) Done() {
	close(rpc.msgs)
}

// Call implements mino.RPC.
func (rpc *RPC) Call(ctx context.Context,
	m serde.Message, p mino.Players) (<-chan mino.Response, error) {

	rpc.Calls.Add(ctx, m, p)

	return rpc.msgs, rpc.err
}

// Stream implements mino.RPC.
func (rpc *RPC) Stream(ctx context.Context, p mino.Players) (mino.Sender, mino.Receiver, error) {
	rpc.Calls.Add(ctx, p)

	return rpc.sender, rpc.receiver, rpc.err
}

// Reset resets the channels.
func (rpc *RPC) Reset() {
	rpc.Calls = &Call{}
	rpc.msgs = make(chan mino.Response, 100)
}

// Mino is a fake implementation of mino.
//
// - implements mino.Mino
type Mino struct {
	mino.Mino
	err error
}

// NewBadMino returns a Mino instance that returns an error when appropriate.
func NewBadMino() Mino {
	return Mino{err: fakeErr}
}

// GetAddress implements mino.Mino.
func (m Mino) GetAddress() mino.Address {
	if m.err != nil {
		return NewBadAddress()
	}

	return Address{}
}

// GetAddressFactory implements mino.Mino.
func (m Mino) GetAddressFactory() mino.AddressFactory {
	return AddressFactory{}
}

// WithSegment implements mino.Mino.
func (m Mino) WithSegment(segment string) mino.Mino {
	return m
}

// CreateRPC implements mino.Mino.
func (m Mino) CreateRPC(string, mino.Handler, serde.Factory) (mino.RPC, error) {
	return NewRPC(), nil
}

// MakeCertificate generates a valid certificate for the localhost address and
// for an hour. It outputs only its byte representation.
func MakeCertificate(t *testing.T, ips ...net.IP) []byte {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IPAddresses:           ips,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	buf, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	return buf
}

// MakeFullCertificate generates a valid certificate for the localhost address
// and for an hour. it outputs the TLS certificate and its byte representation.
func MakeFullCertificate(t *testing.T) (*tls.Certificate, []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IPAddresses:           []net.IP{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	buf, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(buf)
	require.NoError(t, err)

	return &tls.Certificate{
		Certificate: [][]byte{buf},
		PrivateKey:  priv,
		Leaf:        cert,
	}, buf
}

// MakeCertificateChain creates a valid certificate chain with an intermediary
// certificate.
func MakeCertificateChain(t *testing.T) []byte {
	root, pk := makeRootCertificate(t)
	intermediary, pk2 := makeIntermediaryCertificate(t, root, pk)
	server, _ := makeServerCertificate(t, intermediary, pk2)

	chain := bytes.Buffer{}
	chain.Write(server.Raw)
	chain.Write(intermediary.Raw)
	chain.Write(root.Raw)

	return chain.Bytes()
}

func genCert(t *testing.T, template, parent *x509.Certificate,
	publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) *x509.Certificate {

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return cert
}

func makeRootCertificate(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	var template = x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	rootCert := genCert(t, &template, &template, &priv.PublicKey, priv)

	return rootCert, priv
}

func makeIntermediaryCertificate(t *testing.T, rootCert *x509.Certificate,
	rootKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {

	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	var template = x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	intermediary := genCert(t, &template, rootCert, &priv.PublicKey, rootKey)

	return intermediary, priv
}

func makeServerCertificate(t *testing.T, intermediaryCert *x509.Certificate,
	intermediaryKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {

	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	var template = x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageCRLSign,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
	}

	ServerCert := genCert(t, &template, intermediaryCert, &priv.PublicKey, intermediaryKey)

	return ServerCert, priv
}

package pedersen

import (
	"crypto/sha256"
	// "encoding/hex"
	"fmt"
	"math"

	// "unsafe"

	// "math/rand"
	"sync"
	"time"

	"go.dedis.ch/dela"

	"go.dedis.ch/dela/crypto/ed25519"
	"go.dedis.ch/dela/dkg"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"go.dedis.ch/dela/crypto"
	"go.dedis.ch/dela/dkg/pedersen/types"
	"go.dedis.ch/dela/internal/tracing"
	"go.dedis.ch/dela/mino"
	"go.dedis.ch/dela/serde"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/share/pvss"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/util/random"

	"go.dedis.ch/kyber/v3/xof/keccak"
	"golang.org/x/net/context"
	"golang.org/x/xerrors"
)

// suite is the Kyber suite for Pedersen.
var suite = suites.MustFind("Ed25519")

// const GBarString string = "1d0194fdc2fa2ffcc041d3ff12045b73c86e4ff95ff662a5eee82abdf44a53c7"
const GBarString string = "1d0194fdc2fa2ffcc041d3ff12045b73" // 32 bytes
const blockId string = "blockchain ID"

var GBar = suite.Point().Embed([]byte(GBarString), keccak.New([]byte(GBarString)))
var L = gethcrypto.Keccak256([]byte(blockId))

var (
	// protocolNameSetup denotes the value of the protocol span tag associated
	// with the `dkg-setup` protocol.
	protocolNameSetup = "dkg-setup"
	// protocolNameDecrypt denotes the value of the protocol span tag
	// associated with the `dkg-decrypt` protocol.
	protocolNameDecrypt = "dkg-decrypt"
	// ProtocolNameResharing denotes the value of the protocol span tag
	// associated with the `dkg-resharing` protocol.
	protocolNameResharing = "dkg-resharing"
	// number of workers used to perform the encryption/decryption
	//workerNum = runtime.NumCPU()
	workerNumSlice = []int{1, 1, 2, 4, 8, 16, 32, 40, 100, 200, 400, 900}
)

const (
	setupTimeout     = time.Minute * 50
	decryptTimeout   = time.Minute * 5
	resharingTimeout = time.Minute * 5
)

// Pedersen allows one to initialize a new DKG protocol.
//
// - implements dkg.DKG
type Pedersen struct {
	privKey kyber.Scalar
	mino    mino.Mino
	factory serde.Factory
}

// NewPedersen returns a new DKG Pedersen factory
func NewPedersen(m mino.Mino) (*Pedersen, kyber.Point) {
	factory := types.NewMessageFactory(m.GetAddressFactory())

	privkey := suite.Scalar().Pick(suite.RandomStream())
	pubkey := suite.Point().Mul(privkey, nil)

	return &Pedersen{
		privKey: privkey,
		mino:    m,
		factory: factory,
	}, pubkey
}

// Listen implements dkg.DKG. It must be called on each node that participates
// in the DKG. Creates the RPC.
func (s *Pedersen) Listen() (dkg.Actor, error) {
	h := NewHandler(s.privKey, s.mino.GetAddress())

	a := &Actor{
		rpc:      mino.MustCreateRPC(s.mino, "dkg", h, s.factory),
		factory:  s.factory,
		startRes: h.startRes,
	}

	return a, nil
}

// Actor allows one to perform DKG operations like encrypt/decrypt a message
//
// - implements dkg.Actor
type Actor struct {
	rpc      mino.RPC
	factory  serde.Factory
	startRes *state
}

// Setup implement dkg.Actor. It initializes the DKG.
func (a *Actor) Setup(co crypto.CollectiveAuthority, threshold int) (kyber.Point, error) {

	if a.startRes.Done() {
		return nil, xerrors.Errorf("startRes is already done, only one setup call is allowed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, tracing.ProtocolKey, protocolNameSetup)

	sender, receiver, err := a.rpc.Stream(ctx, co)
	if err != nil {
		return nil, xerrors.Errorf("failed to stream: %v", err)
	}

	addrs := make([]mino.Address, 0, co.Len())
	pubkeys := make([]kyber.Point, 0, co.Len())

	addrIter := co.AddressIterator()
	pubkeyIter := co.PublicKeyIterator()

	for addrIter.HasNext() && pubkeyIter.HasNext() {
		addrs = append(addrs, addrIter.GetNext())

		pubkey := pubkeyIter.GetNext()
		edKey, ok := pubkey.(ed25519.PublicKey)
		if !ok {
			return nil, xerrors.Errorf("expected ed25519.PublicKey, got '%T'", pubkey)
		}

		pubkeys = append(pubkeys, edKey.GetPoint())
	}

	//change the message inside to make DKG pure PVSS
	message := types.NewStart(threshold, addrs, pubkeys)

	errs := sender.Send(message, addrs...)
	err = <-errs
	if err != nil {
		return nil, xerrors.Errorf("failed to send start: %v", err)
	}

	dkgPubKeys := make([]kyber.Point, len(addrs))

	for i := 0; i < len(addrs); i++ {

		addr, msg, err := receiver.Recv(context.Background())
		if err != nil {
			fmt.Println("msg", msg)
			return nil, xerrors.Errorf("got an error from '%s' while "+
				"receiving: %v", addr, err)
		}
		doneMsg, ok := msg.(types.StartDone)
		if !ok {
			return nil, xerrors.Errorf("expected to receive a Done message, but "+
				"go the following: %T", msg)
		}

		dela.Logger.Info().Msgf("node %q done", addr.String())

		dkgPubKeys[i] = doneMsg.GetPublicKey()

		// this is a simple check that every node sends back the same DKG pub
		// key.
		// TODO: handle the situation where a pub key is not the same
		if i != 0 && !dkgPubKeys[i-1].Equal(doneMsg.GetPublicKey()) {
			return nil, xerrors.Errorf("the public keys does not match: %v", dkgPubKeys)
		}
	}

	return dkgPubKeys[0], nil
}

// GetPublicKey implements dkg.Actor
func (a *Actor) GetPublicKey() (kyber.Point, error) {
	if !a.startRes.Done() {
		return nil, xerrors.Errorf("DKG has not been initialized")
	}

	return a.startRes.getDistKey(), nil
}

// Encrypt implements dkg.Actor. It uses the DKG public key to encrypt a
// message.
func (a *Actor) Encrypt(message []byte) (K, C kyber.Point, remainder []byte,
	err error) {

	if !a.startRes.Done() {
		return nil, nil, nil, xerrors.Errorf("you must first initialize DKG. " +
			"Did you call setup() first?")
	}

	// Embed the message (or as much of it as will fit) into a curve point.
	M := suite.Point().Embed(message, random.New())
	max := suite.Point().EmbedLen()
	if max > len(message) {
		max = len(message)
	}
	remainder = message[max:]
	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := suite.Scalar().Pick(random.New())             // ephemeral private key
	K = suite.Point().Mul(k, nil)                      // ephemeral DH public key
	S := suite.Point().Mul(k, a.startRes.getDistKey()) // ephemeral DH shared secret
	C = S.Add(S, M)                                    // message blinded with secret

	return K, C, remainder, nil
}

// VerifiableEncrypt implements dkg.Actor. It uses the DKG public key to encrypt
// a message and provide a zero knowledge proof that the encryption is done by
// this person.
//
// See https://arxiv.org/pdf/2205.08529.pdf / section 5.4 Protocol / step 1
func (a *Actor) VerifiableEncrypt(message []byte, GBarAbort kyber.Point) (ciphertext types.Ciphertext,
	remainder []byte, err error) {
	//remove GBarAbort in all places

	if !a.startRes.Done() {
		return types.Ciphertext{}, nil, xerrors.Errorf("you must first initialize " +
			"DKG. Did you call setup() first?")
	}
	// Embed the message (or as much of it as will fit) into a curve point.
	M := suite.Point().Embed(message, random.New())

	max := suite.Point().EmbedLen()
	if max > len(message) {
		max = len(message)
	}

	remainder = message[max:]

	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := suite.Scalar().Pick(random.New())             // ephemeral private key
	K := suite.Point().Mul(k, nil)                     // ephemeral DH public key
	S := suite.Point().Mul(k, a.startRes.getDistKey()) // ephemeral DH shared secret
	C := S.Add(S, M)                                   // message blinded with secret

	// producing the zero knowledge proof
	UBar := suite.Point().Mul(k, GBar)
	s := suite.Scalar().Pick(random.New())
	W := suite.Point().Mul(s, nil)
	WBar := suite.Point().Mul(s, GBar)

	hash := sha256.New()
	C.MarshalTo(hash)
	K.MarshalTo(hash)
	UBar.MarshalTo(hash)
	W.MarshalTo(hash)
	WBar.MarshalTo(hash)
	// implement L to prevent replay attack
	hash.Write(L)

	E := suite.Scalar().SetBytes(hash.Sum(nil))
	F := suite.Scalar().Add(s, suite.Scalar().Mul(E, k))

	ciphertext = types.Ciphertext{
		K:    K,
		C:    C,
		UBar: UBar,
		E:    E,
		F:    F,
		// GBar: GBar,
	}
	// fmt.Println("length of ciphertext", unsafe.Sizeof(ciphertext))
	//check the length of the ciphertext in two ways, add all length of the contents and check directly the whole length
	// fmt.Println("length of ciphertext", len(ciphertext.K.String())+len(ciphertext.C.String())+len(ciphertext.UBar.String())+len(ciphertext.E.String())+len(ciphertext.F.String())+len(ciphertext.GBar.String()))

	return ciphertext, remainder, nil
}

// PVSSenc implements dkg.Actor. It splits the message into multiple shares.
// This is planned to fit symmetric key generated by F3B. Not used right now. Below is the handover version.
// This fuction is modified from Calypso.
// n is the number of participants, t is the threshold, pubs are their public keys, darc is the access control policy
// generally I think the n equals to co.Len()? We also need to guarantee that n < co.Len(). TODO: check this
// since we need the identity of the participants, we need to pass the cothority to have the public keys
// suite is the global suite and we don't need to pass it here. When migrate to the new version, check that suite will be accessed.
// pubs are inside the cothority, just pass the cothority and get the public keys. TODO: preprare a function to get the public keys
func (a *Actor) RunPVSS(n int, t int, co crypto.CollectiveAuthority) ([]*pvss.PubVerShare, *share.PubPoly, kyber.Scalar, error) {

	h := GBar

	// what is the length of the secret? Should this be consistent with the definition in F3B? TODO: check this
	secret := suite.Scalar().Pick(suite.RandomStream())

	// here we get the public keys directly from the states
	pubkeys := a.startRes.getPublicKeys()
	// start := time.Now()

	//notice that here the h will be used for decryption, so we need to publish it. In this case, it is important to consider where to generate h and how to publish it.
	shares, poly, err := pvss.EncShares(suite, h, pubkeys, secret, t)
	// _, commit := poly.Info()
	// In poly, g is suite and b is gbar, only the commit is needed to be store in transactions.
	//check the length of shares and poly
	// lenShare := len(shares) * (len(shares[0].S.V.String()) + 8 + len(shares[0].P.C.String()) + len(shares[0].P.R.String()) + len(shares[0].P.VG.String()) + len(shares[0].P.VH.String()))

	//add everything together
	//actually we should add h somewhere in our protocol and publish it, but for now we just dont count it
	// fmt.Println("length of everything", lenShare+poly.GetLength()+len(shares)*8)
	// LG := unsafe.Sizeof(poly.GetGroup())
	// B, C := poly.Info()
	// LC := unsafe.Sizeof(C[1])
	// LB := unsafe.Sizeof(B)
	// LS := unsafe.Sizeof(*shares[0])
	// fmt.Println("length of all", LS, LG, LB, unsafe.Sizeof(poly.Commit()), LC, poly.Threshold(), len(shares)*8)
	// fmt.Println("length of everything", int(LS)*len(shares)+int(LG)+int(LB)+int(LC)*poly.Threshold()+int(poly.Threshold())*8)

	// generateShareTime := time.Since(start).Milliseconds()
	// fmt.Println("generateShareTime is: ", generateShareTime)

	//check here, the verification takes a lot of time.
	// sH is the public commitment computed by evaluating the public commitment polynomial at the encrypted share's index i.  sH kyber.Point
	// sH := make([]kyber.Point, n)
	// for i := 0; i < n; i++ {
	// 	sH[i] = poly.Eval(shares[i].S.I).V
	// }
	// // let's think, this verify is not accessible to non-participants because they dont know h. So we either publish h, or generate another proof.
	// K, E, err := pvss.VerifyEncShareBatch(suite, h, pubkeys, sH, shares)
	// if len(K) != n || len(E) != n {
	// 	fmt.Println("K is: ", K)
	// 	fmt.Println("E is: ", E)
	// 	fmt.Println("error in verifyEncShare", err)
	// 	return nil, nil, nil, nil, err
	// }

	// But surely there is a verify in decrypt function to make sure shares are received by the actor in charge. Check that for PVSS recover.

	if err != nil {
		fmt.Println("error in RUNPVSS", err)
		return nil, nil, nil, err
	}

	return shares, poly, secret, nil
}

// using cothority to replace X the public keys of the participants.
// x is the private key of the participants. This is stored in the Pedersen struct. It remains to be seen what is the best way to get the private key.
// in the handler x can be directly accessed? So here we do not need to pass the argument x. TODO: check this
// another thing to notice is that the DecPVSS is highly common with part of DKG progress, consider codes reuse? Similar to VerifiableDecryption?
// sH is the public commitment computed by evaluating the public commitment polynomial at the encrypted share's index i.  sH kyber.Point
// sH := make([]kyber.Point, n)
//
//	for i := 0; i < n; i++ {
//		sH[i] = pubPoly.Eval(encShares[i].S.I).V
//	}
//
// use the above code to get sH. TODO: check where to put this. Might better use it inside of the handler.
func (a *Actor) DecPVSS(pubpoly *share.PubPoly, encShare [][]*pvss.PubVerShare) ([][]byte, int64, int64, error) {
	//remove H because it's stored globally
	if !a.startRes.Done() {
		return nil, 0, 0, xerrors.Errorf("you must first initialize DKG. " +
			"Did you call setup() first?")
	}

	players := mino.NewAddresses(a.startRes.getParticipants()...)

	ctx, cancel := context.WithTimeout(context.Background(), decryptTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, tracing.ProtocolKey, protocolNameDecrypt)

	sender, receiver, err := a.rpc.Stream(ctx, players)
	if err != nil {
		return nil, 0, 0, xerrors.Errorf("failed to create stream: %v", err)
	}

	players = mino.NewAddresses(a.startRes.getParticipants()...)
	iterator := players.AddressIterator()

	addrs := make([]mino.Address, 0, players.Len())
	// fmt.Println(addrs)
	for iterator.HasNext() {
		addrs = append(addrs, iterator.GetNext())
	}

	//adding support for batch process
	batchsize := len(encShare)
	workerNum := workerNumSlice[int64(math.Log2(float64(batchsize)))]

	//send the whole shares to all participants
	// revise this by using the batch process. also include the proof.
	message := types.NewDecPVSSRequest(encShare)

	start := time.Now()

	err = <-sender.Send(message, addrs...)
	if err != nil {
		return nil, 0, 0, xerrors.Errorf("failed to send pvss decrypt request: %v", err)
	}

	//check here, add the verification of the proof.

	threshold := a.startRes.getThreshold()
	//initialize decShares and encShares
	decShares := make([][]*pvss.PubVerShare, batchsize)
	encShares := make([][]*pvss.PubVerShare, batchsize)
	for i := range encShares {
		encShares[i] = make([]*pvss.PubVerShare, threshold)
		decShares[i] = make([]*pvss.PubVerShare, threshold)
	}
	// fmt.Println("EncShare: ", encShare)

	pubKeys := make([]kyber.Point, threshold)

	// receive decrypt reply from the nodes
	for i := 0; i < threshold; i++ {
		// fmt.Println(i)
		//bugs solved! no return value in message stream.
		from, message, err := receiver.Recv(ctx)
		if err != nil {
			return nil, 0, 0, xerrors.Errorf("stream stopped unexpectedly: %v", err)
		}

		dela.Logger.Debug().Msgf("received share from %v\n", from)

		decShare, ok := message.(types.DecPVSSReply)
		// fmt.Println("decShare: ", decShare)
		if !ok {
			return nil, 0, 0, xerrors.Errorf("got unexpected reply, expected "+
				"%T but got: %T", decShare, message)
		}

		// fmt.Println(decShare.GetDecShares()[0].S)
		position := decShare.GetIndex()
		// fmt.Println("position: ", position)
		// index the batched shares into the corresponding position
		for j := 0; j < batchsize; j++ {
			encShares[j][i] = encShare[j][position]
			decShares[j][i] = decShare.GetDecShares()[j]
		}
		// encShares[i] = encShare[0][position]
		// decShares[i] = decShare.GetDecShares()[0]
		pubKeys[i] = a.startRes.getPublicKeys()[position]
		// decShares[position] = decShare.GetDecShares()[0]
	}

	// the RecoverCommit runs the Lagrange interpolation on the shares to recover the secret. arguments are t and n.
	receivingSharesTime := time.Since(start).Milliseconds()
	start = time.Now()

	// the final decrypted message
	decryptedSecret := make([][]byte, batchsize)

	var wgBatchReply sync.WaitGroup
	jobChan := make(chan int)

	go func() {
		for i := 0; i < batchsize; i++ {
			jobChan <- i
		}

		close(jobChan)
	}()

	if batchsize < workerNum {
		workerNum = batchsize
	}

	worker := newWorkerPVSS(len(addrs), threshold, pubKeys, decryptedSecret, decShares, encShares)

	for i := 0; i < workerNum; i++ {
		wgBatchReply.Add(1)

		go func() {
			defer wgBatchReply.Done()
			for j := range jobChan {
				err := worker.workPVSS(j)
				if err != nil {
					dela.Logger.Err(err).Msgf("error in a worker")
				}
			}
		}()
	}

	wgBatchReply.Wait()

	// count the time for decryption
	decryptionTime := time.Since(start).Milliseconds()

	return decryptedSecret, receivingSharesTime, decryptionTime, nil
}

// Decrypt implements dkg.Actor. It gets the private shares of the nodes and
// decrypt the  message.
func (a *Actor) Decrypt(K, C kyber.Point) ([]byte, error) {

	if !a.startRes.Done() {
		return nil, xerrors.Errorf("you must first initialize DKG. " +
			"Did you call setup() first?")
	}

	players := mino.NewAddresses(a.startRes.getParticipants()...)

	ctx, cancel := context.WithTimeout(context.Background(), decryptTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, tracing.ProtocolKey, protocolNameDecrypt)

	sender, receiver, err := a.rpc.Stream(ctx, players)
	if err != nil {
		return nil, xerrors.Errorf("failed to create stream: %v", err)
	}

	players = mino.NewAddresses(a.startRes.getParticipants()...)
	iterator := players.AddressIterator()

	addrs := make([]mino.Address, 0, players.Len())
	for iterator.HasNext() {
		addrs = append(addrs, iterator.GetNext())
	}

	message := types.NewDecryptRequest(K, C)

	err = <-sender.Send(message, addrs...)
	if err != nil {
		return nil, xerrors.Errorf("failed to send decrypt request: %v", err)
	}

	pubShares := make([]*share.PubShare, len(addrs))

	for i := 0; i < len(addrs); i++ {
		src, message, err := receiver.Recv(ctx)
		if err != nil {
			return []byte{}, xerrors.Errorf("stream stopped unexpectedly: %v", err)
		}

		dela.Logger.Debug().Msgf("Received a decryption reply from %v", src)

		decryptReply, ok := message.(types.DecryptReply)
		if !ok {
			return []byte{}, xerrors.Errorf("got unexpected reply, expected "+
				"%T but got: %T", decryptReply, message)
		}

		pubShares[i] = &share.PubShare{
			I: int(decryptReply.I),
			V: decryptReply.V,
		}
	}

	res, err := share.RecoverCommit(suite, pubShares, len(addrs), len(addrs))
	if err != nil {
		return []byte{}, xerrors.Errorf("failed to recover commit: %v", err)
	}

	decryptedMessage, err := res.Data()
	if err != nil {
		return []byte{}, xerrors.Errorf("failed to get embeded data: %v", err)
	}

	dela.Logger.Info().Msgf("Decrypted message: %v", decryptedMessage)

	return decryptedMessage, nil
}

// VerifiableDecrypt implements dkg.Actor. It does as Decrypt() but in addition
// it checks whether the decryption proofs are valid.
//
// See https://arxiv.org/pdf/2205.08529.pdf / section 5.4 Protocol / step 3
func (a *Actor) VerifiableDecrypt(ciphertexts []types.Ciphertext) ([][]byte, int64, int64, error) {

	if !a.startRes.Done() {
		return nil, 0, 0, xerrors.Errorf("you must first initialize DKG. " +
			"Did you call setup() first?")
	}

	players := mino.NewAddresses(a.startRes.getParticipants()...)

	ctx, cancel := context.WithTimeout(context.Background(), decryptTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, tracing.ProtocolKey, protocolNameDecrypt)

	sender, receiver, err := a.rpc.Stream(ctx, players)
	if err != nil {
		return nil, 0, 0, xerrors.Errorf("failed to create stream: %v", err)
	}

	players = mino.NewAddresses(a.startRes.getParticipants()...)
	iterator := players.AddressIterator()

	addrs := make([]mino.Address, 0, players.Len())
	for iterator.HasNext() {
		addrs = append(addrs, iterator.GetNext())
	}
	// fmt.Println(addrs)

	// fmt.Println(ciphertexts)
	// Here the batchsize is predefined in test file, every ciphertext contains 6 data as defined, K,C,U...
	batchsize := len(ciphertexts)
	workerNum := workerNumSlice[int64(math.Log2(float64(batchsize)))]

	message := types.NewVerifiableDecryptRequest(ciphertexts)
	// fmt.Println(message)
	start := time.Now()

	err = <-sender.Send(message, addrs...)
	if err != nil {
		return nil, 0, 0, xerrors.Errorf("failed to send verifiable decrypt request: %v", err)
	}

	threshold := a.startRes.getThreshold()
	// responses := make([]types.VerifiableDecryptReply, len(addrs))
	responses := make([]types.VerifiableDecryptReply, threshold)
	// start := time.Now()
	// receive decrypt reply from the nodes

	// fmt.Println("threshold: ", threshold)
	for i := range addrs {
		// fmt.Println(i)
		from, message, err := receiver.Recv(ctx)
		if err != nil {
			return nil, 0, 0, xerrors.Errorf("stream stopped unexpectedly: %v", err)
		}

		dela.Logger.Debug().Msgf("received share from %v\n", from)

		shareAndProof, ok := message.(types.VerifiableDecryptReply)
		if !ok {
			return nil, 0, 0, xerrors.Errorf("got unexpected reply, expected "+
				"%T but got: %T", shareAndProof, message)
		}

		responses[i] = shareAndProof
		// exit the loop after receiving threshold number of shares
		if i == threshold-1 {
			break
		}
	}

	receivingSharesTime := time.Since(start).Milliseconds()
	start = time.Now()

	// the final decrypted message
	decryptedMessage := make([][]byte, batchsize)

	var wgBatchReply sync.WaitGroup
	jobChan := make(chan int)

	go func() {
		for i := 0; i < batchsize; i++ {
			jobChan <- i
		}

		close(jobChan)
	}()

	if batchsize < workerNum {
		workerNum = batchsize
	}

	worker := newWorker(len(addrs), threshold, decryptedMessage, responses, ciphertexts)

	for i := 0; i < workerNum; i++ {
		wgBatchReply.Add(1)

		go func() {
			defer wgBatchReply.Done()
			for j := range jobChan {
				err := worker.work(j)
				if err != nil {
					dela.Logger.Err(err).Msgf("error in a worker")
				}
			}
		}()
	}

	wgBatchReply.Wait()

	decryptionTime := time.Since(start).Milliseconds()

	return decryptedMessage, receivingSharesTime, decryptionTime, nil
}

// define worker for pvss
func newWorkerPVSS(numParticipants int, threshold int, publicKeys []kyber.Point, decSecrets [][]byte,
	decShares [][]*pvss.PubVerShare, encShares [][]*pvss.PubVerShare) workerPVSS {

	return workerPVSS{
		numParticipants: numParticipants,
		threshold:       threshold,
		publicKeys:      publicKeys,
		decSecrets:      decSecrets,
		decShares:       decShares,
		encShares:       encShares,
	}
}

// define worker for pvss
type workerPVSS struct {
	numParticipants int
	threshold       int
	publicKeys      []kyber.Point
	decSecrets      [][]byte
	decShares       [][]*pvss.PubVerShare
	encShares       [][]*pvss.PubVerShare
}

// implement work function for pvss
func (w workerPVSS) workPVSS(jobIndex int) error {
	//check encshares and decshares again
	// fmt.Println("encshares:", w.encShares[jobIndex])
	// fmt.Println("decshares:", w.decShares[jobIndex])
	res, err := pvss.RecoverSecret(suite, suite.Point().Base(), w.publicKeys, w.encShares[jobIndex], w.decShares[jobIndex], w.threshold, w.numParticipants)
	if err != nil {
		fmt.Println("err:", err)
		return xerrors.Errorf("failed to recover the commit: %v", err)
	}

	buf, err := deriveKey(res)
	if err != nil {
		return xerrors.Errorf("failed to derive key: %v", err)
	}
	deckey := buf[:32]

	w.decSecrets[jobIndex] = deckey

	return nil
}

func newWorker(numParticipants int, threshold int, decryptedMessage [][]byte,
	responses []types.VerifiableDecryptReply, ciphertexts []types.Ciphertext) worker {

	return worker{
		numParticipants:  numParticipants,
		threshold:        threshold,
		decryptedMessage: decryptedMessage,
		responses:        responses,
		ciphertexts:      ciphertexts,
	}
}

// worker contains the data needed by a worker to perform the verifiable
// decryption job. All its fields must be read-only, except the
// decryptedMessage, which can be written at a provided jobIndex.
type worker struct {
	numParticipants  int
	threshold        int
	decryptedMessage [][]byte
	ciphertexts      []types.Ciphertext
	responses        []types.VerifiableDecryptReply
}

func (w worker) work(jobIndex int) error {
	pubShares := make([]*share.PubShare, w.numParticipants)

	for k, response := range w.responses {
		resp := response.GetShareAndProof()[jobIndex]

		err := checkDecryptionProof(resp, w.ciphertexts[jobIndex].K)
		if err != nil {
			return xerrors.Errorf("failed to check the decryption proof: %v", err)
		}

		pubShares[k] = &share.PubShare{
			I: int(resp.I),
			V: resp.V,
		}
	}

	res, err := share.RecoverCommit(suite, pubShares, w.threshold, w.numParticipants)
	// fmt.Println("res:", res)
	if err != nil {
		return xerrors.Errorf("failed to recover the commit: %v", err)
	}

	w.decryptedMessage[jobIndex], err = res.Data()
	if err != nil {
		return xerrors.Errorf("failed to get embedded data : %v", err)
	}

	return nil
}

// Reshare implements dkg.Actor. It recreates the DKG with an updated list of
// participants.
func (a *Actor) Reshare(co crypto.CollectiveAuthority, thresholdNew int) error {
	if !a.startRes.Done() {
		return xerrors.Errorf("you must first initialize DKG. " +
			"Did you call setup() first?")
	}

	addrsNew := make([]mino.Address, 0, co.Len())
	pubkeysNew := make([]kyber.Point, 0, co.Len())

	addrIter := co.AddressIterator()
	pubkeyIter := co.PublicKeyIterator()

	for addrIter.HasNext() && pubkeyIter.HasNext() {
		addrsNew = append(addrsNew, addrIter.GetNext())

		pubkey := pubkeyIter.GetNext()

		edKey, ok := pubkey.(ed25519.PublicKey)
		if !ok {
			return xerrors.Errorf("expected ed25519.PublicKey, got '%T'", pubkey)
		}

		pubkeysNew = append(pubkeysNew, edKey.GetPoint())
	}

	// Get the union of the new members and the old members
	addrsAll := union(a.startRes.getParticipants(), addrsNew)
	players := mino.NewAddresses(addrsAll...)

	ctx, cancel := context.WithTimeout(context.Background(), resharingTimeout)
	defer cancel()

	ctx = context.WithValue(ctx, tracing.ProtocolKey, protocolNameResharing)

	dela.Logger.Info().Msgf("resharing with the following participants: %v", addrsAll)

	sender, receiver, err := a.rpc.Stream(ctx, players)
	if err != nil {
		return xerrors.Errorf("failed to create stream: %v", err)
	}

	thresholdOld := a.startRes.getThreshold()
	pubkeysOld := a.startRes.getPublicKeys()

	// We don't need to send the old threshold or old public keys to the old or
	// common nodes
	reshare := types.NewStartResharing(thresholdNew, 0, addrsNew, nil, pubkeysNew, nil)

	dela.Logger.Info().Msgf("resharing to old participants: %v",
		a.startRes.getParticipants())

	// Send the resharing request to the old and common nodes
	err = <-sender.Send(reshare, a.startRes.getParticipants()...)
	if err != nil {
		return xerrors.Errorf("failed to send resharing request: %v", err)
	}

	// First find the set of new nodes that are not common between the old and
	// new committee
	newParticipants := difference(addrsNew, a.startRes.getParticipants())

	// Then create a resharing request message for them. We should send the old
	// threshold and old public keys to them
	reshare = types.NewStartResharing(thresholdNew, thresholdOld, addrsNew,
		a.startRes.getParticipants(), pubkeysNew, pubkeysOld)

	dela.Logger.Info().Msgf("resharing to new participants: %v", newParticipants)

	// Send the resharing request to the new but not common nodes
	if len(newParticipants) != 0 {
		err = <-sender.Send(reshare, newParticipants...)
		if err != nil {
			return xerrors.Errorf("failed to send resharing request: %v", err)
		}
	}

	dkgPubKeys := make([]kyber.Point, len(addrsAll))

	// Wait for receiving the response from the new nodes
	for i := 0; i < len(addrsAll); i++ {
		src, msg, err := receiver.Recv(ctx)
		if err != nil {
			return xerrors.Errorf("stream stopped unexpectedly: %v", err)
		}

		doneMsg, ok := msg.(types.StartDone)
		if !ok {
			return xerrors.Errorf("expected to receive a Done message, but "+
				"got the following: %T, from %s", msg, src.String())
		}

		dkgPubKeys[i] = doneMsg.GetPublicKey()

		dela.Logger.Debug().Str("from", src.String()).Msgf("received a done reply")

		// This is a simple check that every node sends back the same DKG pub
		// key.
		// TODO: handle the situation where a pub key is not the same
		if i != 0 && !dkgPubKeys[i-1].Equal(doneMsg.GetPublicKey()) {
			return xerrors.Errorf("the public keys does not match: %v", dkgPubKeys)
		}
	}

	dela.Logger.Info().Msgf("resharing done")

	return nil
}

// checkDecryptionProof verifies the decryption proof.
//
// See https://arxiv.org/pdf/2205.08529.pdf / section 5.4 Protocol / step 3
func checkDecryptionProof(sp types.ShareAndProof, K kyber.Point) error {

	tmp1 := suite.Point().Mul(sp.Fi, K)
	tmp2 := suite.Point().Mul(sp.Ei, sp.Ui)
	UHat := suite.Point().Sub(tmp1, tmp2)

	tmp1 = suite.Point().Mul(sp.Fi, nil)
	tmp2 = suite.Point().Mul(sp.Ei, sp.Hi)
	HHat := suite.Point().Sub(tmp1, tmp2)

	hash := sha256.New()
	sp.Ui.MarshalTo(hash)
	UHat.MarshalTo(hash)
	HHat.MarshalTo(hash)
	tmp := suite.Scalar().SetBytes(hash.Sum(nil))

	if !tmp.Equal(sp.Ei) {
		return xerrors.Errorf("hash is not valid: %x != %x", sp.Ei, tmp)
	}

	return nil
}

// difference performs "el1 difference el2", i.e. it extracts all members of el1
// that are not present in el2.
func difference(el1 []mino.Address, el2 []mino.Address) []mino.Address {
	var result []mino.Address

	for _, addr1 := range el1 {
		exist := false
		for _, addr2 := range el2 {
			if addr1.Equal(addr2) {
				exist = true
				break
			}
		}

		if !exist {
			result = append(result, addr1)
		}
	}

	return result
}

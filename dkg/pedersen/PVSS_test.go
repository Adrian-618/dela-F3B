package pedersen

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"time"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/dela/dkg"
	"go.dedis.ch/dela/mino"

	"go.dedis.ch/dela/mino/minoch"
	"go.dedis.ch/dela/mino/minogrpc"
	"go.dedis.ch/dela/mino/router/tree"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/share/pvss"
	"go.dedis.ch/kyber/v3/xof/keccak"
)

func init() {
	rand.Seed(0)
}

func Test_RunPVSS(t *testing.T) {
	// setup up the dkg
	n := 16
	threshold := n
	// batchSize := 1

	minos := make([]mino.Mino, n)
	dkgs := make([]dkg.DKG, n)
	addrs := make([]mino.Address, n)

	agreedData := make([]byte, 32)
	_, err := rand.Read(agreedData)
	require.NoError(t, err)

	minoManager := minoch.NewManager()

	for i := 0; i < n; i++ {
		minoch := minoch.MustCreate(minoManager, fmt.Sprintf("addr %d", i))
		minos[i] = minoch
		addrs[i] = minoch.GetAddress()
	}

	pubkeys := make([]kyber.Point, len(minos))
	// prikeys := make([]kyber.Scalar, len(minos))

	for i, mino := range minos {
		dkg, pubkey := NewPedersen(mino)
		dkgs[i] = dkg
		pubkeys[i] = pubkey
		// prikeys[i] = (*dkg).privKey
	}

	fakeAuthority := NewAuthority(addrs, pubkeys)

	actors := make([]dkg.Actor, n)
	for i := 0; i < n; i++ {
		actor, err := dkgs[i].Listen()
		require.NoError(t, err)
		actors[i] = actor
	}

	t.Log("setting up the dkg ...")

	_, err = actors[0].Setup(fakeAuthority, threshold)
	require.NoError(t, err)

	t.Log("generating the message and encrypting it ...")

	//essentailly the thing is, after dkg is set up, any actor can control the actions. Remember that PVSS actually needs a different yet simpler setup.
	start := time.Now()
	shares, pubpoly, symkey, err := actors[0].RunPVSS(n, threshold, fakeAuthority)
	encryptTime := time.Since(start)
	fmt.Println("encrypt time is: ", encryptTime)
	shared := suite.Point().Mul(symkey, nil)
	buf, err := deriveKey(shared)
	enckey := buf[:KEY_LENGTH]
	fmt.Println("enckey", enckey)

	// TODO: check if we need to verify the proof
	// fmt.Println(proofs)
	// thinking that batch size is 1, we can use the following to fool the DecPVSS function.
	// in real case mostlikely we can just do things similar:
	fakebatchShares := [][]*pvss.PubVerShare{shares}
	// fmt.Println(fakebatchShares)
	//attention! Here a random H is feed into the DecPVSS function as I disable all the related verify process in the DecPVSS function.
	start = time.Now()
	decKey, rcvTime, decTime, err := actors[0].DecPVSS(pubpoly, fakebatchShares)
	decryptionTime := time.Since(start)
	fmt.Println("decryption time is: ", decryptionTime)
	fmt.Println("decKey is: ", decKey)
	fmt.Println("rcvTime and decTime(ms): ", rcvTime, decTime)
}

func Test_PVSS_minogrpc(t *testing.T) {
	// minoch is simulated communication, and grpc is more realistic and should be used here

	batchSizeSlice := []int{512}

	// setting up the dkg
	n := 128
	threshold := n/2 + 1

	minos := make([]mino.Mino, n)
	dkgs := make([]dkg.DKG, n)
	addrs := make([]mino.Address, n)

	// Here I wonder if we need the gbar for pvss. After all we don't run the DKG setup, maybe a random generator is fine?
	agreedData := make([]byte, 32)
	_, err := rand.Read(agreedData)
	require.NoError(t, err)
	// GBar := suite.Point().Embed(agreedData, keccak.New(agreedData))

	t.Log("initiating the dkg nodes ...")
	fmt.Printf("initiating the dkg nodes ...")

	for i := 0; i < n; i++ {
		addr := minogrpc.ParseAddress("127.0.0.1", 0)

		minogrpc, err := minogrpc.NewMinogrpc(addr, nil, tree.NewRouter(minogrpc.NewAddressFactory()))
		require.NoError(t, err)

		defer minogrpc.GracefulStop()

		minos[i] = minogrpc
		addrs[i] = minogrpc.GetAddress()
	}

	pubkeys := make([]kyber.Point, len(minos))

	for i, mino := range minos {
		for _, m := range minos {
			mino.(*minogrpc.Minogrpc).GetCertificateStore().Store(m.GetAddress(),
				m.(*minogrpc.Minogrpc).GetCertificateChain())
		}
		dkg, pubkey := NewPedersen(mino.(*minogrpc.Minogrpc))
		dkgs[i] = dkg
		pubkeys[i] = pubkey
	}

	fakeAuthority := NewAuthority(addrs, pubkeys)

	actors := make([]dkg.Actor, n)
	for i := 0; i < n; i++ {
		actor, err := dkgs[i].Listen()
		require.NoError(t, err)
		actors[i] = actor
	}

	t.Log("setting up the dkg ...")
	fmt.Printf("setting up the dkg ...")
	start := time.Now()
	_, err = actors[0].Setup(fakeAuthority, threshold)
	require.NoError(t, err)
	setupTime := time.Since(start)

	start = time.Now()
	// add batch test support
	for _, batchSize := range batchSizeSlice {
		t.Logf("=== starting the process with batch size = %d === \n", batchSize)
		fmt.Printf("=== starting the process with batch size = %d === \n", batchSize)
		var batchShares [][]*pvss.PubVerShare
		var batchPubPoly []*share.PubPoly
		var batchEnckey [][]byte
		var pubpoly *share.PubPoly
		for i := 0; i < batchSize; i++ {
			shares, pubpoly, symkey, err := actors[0].RunPVSS(n, threshold, fakeAuthority)
			require.NoError(t, err)
			shared := suite.Point().Mul(symkey, nil)
			buf, err := deriveKey(shared)
			enckey := buf[:KEY_LENGTH]
			batchShares = append(batchShares, shares)
			batchPubPoly = append(batchPubPoly, pubpoly)
			batchEnckey = append(batchEnckey, enckey)
		}

		// shares, pubpoly, h, symkey, err := actors[0].RunPVSS(n, threshold, fakeAuthority)
		encryptTime := time.Since(start)
		// fmt.Println("encrypt time is: ", encryptTime)
		// shared := suite.Point().Mul(symkey, nil)
		// buf, err := deriveKey(shared)
		// enckey := buf[:KEY_LENGTH]
		// fmt.Println("enckey", enckey)

		// fakebatchShares := [][]*pvss.PubVerShare{shares}
		fakebatchShares := batchShares // now it's not fake anymore
		t.Log("decrypting the key shares ...")
		fmt.Printf("decrypting the key shares ...")
		start = time.Now()
		//decPVSS need to be modified to support batch decryption for pubpoly
		decKey, rcvTime, decTime, err := actors[0].DecPVSS(pubpoly, fakebatchShares)
		decryptionTime := time.Since(start)
		require.NoError(t, err)

		require.Equal(t, batchEnckey, decKey)

		t.Logf("n=%d, encryption time=%s, decryption time=%s, "+
			"setup time=%s, rcvTime=%d, decTime=%d", n, encryptTime,
			decryptionTime, setupTime, rcvTime, decTime)
		fmt.Printf("n=%d, encryption time=%s, decryption time=%s, "+
			"setup time=%s, rcvTime=%d, decTime=%d", n, encryptTime,
			decryptionTime, setupTime, rcvTime, decTime)
	}
}

func Test_RunPVSS_package(t *testing.T) {
	n := 8
	minos := make([]mino.Mino, n)

	minoManager := minoch.NewManager()

	for i := 0; i < n; i++ {
		minoch := minoch.MustCreate(minoManager, fmt.Sprintf("addr %d", i))
		minos[i] = minoch
	}

	pubkeys := make([]kyber.Point, len(minos))
	prikeys := make([]kyber.Scalar, len(minos))

	for i, mino := range minos {
		dkg, pubkey := NewPedersen(mino)
		pubkeys[i] = pubkey
		prikeys[i] = (*dkg).privKey
	}
	// hash := sha256.New()
	// h := suite.Point().Pick(suite.XOF(hash.Sum(nil)))
	// fmt.Println("h is: ", h)

	agreedData := make([]byte, 32)
	_, err := rand.Read(agreedData)
	require.NoError(t, err)
	GBar := suite.Point().Embed(agreedData, keccak.New(agreedData))

	symKey := make([]byte, 24)
	_, err = rand.Read(symKey)
	if err != nil {
		panic(fmt.Sprintf("failed on load random key: %v", err))
	}

	//let's say, the secret here is not the symkey that can be directly used, so it is not the same as the res we obtained. However with them we can derive the symmetric key.
	// The methods is put in mod_pvss.go
	secret := suite.Scalar().Pick(suite.RandomStream())
	fmt.Println("secret is: ", secret)
	//notice that here the h will be used for decryption, so we need to publish it. In this case, it is important to consider where to generate h and how to publish it.
	encshares, poly, err := pvss.EncShares(suite, GBar, pubkeys, secret, n)
	if err != nil {
		fmt.Println(err)
	}
	sH := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		sH[i] = poly.Eval(encshares[i].S.I).V
	}
	// let's think, this verify is not accessible to non-participants because they dont know h. So we either publish h, or generate another proof.
	K, E, err := pvss.VerifyEncShareBatch(suite, GBar, pubkeys, sH, encshares)
	fmt.Println("K is: ", K)
	fmt.Println("E is: ", E)
	if err != nil {
		fmt.Println(err)
	}
	decShare := make([]*pvss.PubVerShare, n)
	for i := 0; i < n; i++ {
		decShare[i], err = pvss.DecShare(suite, GBar, pubkeys[i], sH[i], prikeys[i], encshares[i])
	}
	fmt.Println("decShare: ", decShare)
	fmt.Println("suite.Point().Base(): ", suite.Point().Base())
	res, err := pvss.RecoverSecret(suite, suite.Point().Base(), pubkeys, encshares, decShare, n, n)
	fmt.Println("res_test", res)
	if err != nil {
		fmt.Println(err)
	}

	mesg1 := []byte("Hello regular OTS #1!")
	fmt.Println("mesg1: ", mesg1)
	ctxt1, ctxtHash1, err := Encrypt_test(suite, secret, mesg1)
	ptxt1, err := Decrypt_test(res, ctxt1)
	fmt.Println("ctxt1: ", ctxt1)
	fmt.Println("ctxtHash1: ", ctxtHash1)
	fmt.Println("ptxt1: ", ptxt1)
	str := bytes.NewBuffer(ptxt1).String()
	fmt.Println("str: ", str)
	// data, err := res.Data()
	// fmt.Println("decKey_test", data)
}

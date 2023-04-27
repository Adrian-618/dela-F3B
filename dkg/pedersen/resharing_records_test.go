package pedersen

import (
	"flag"
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"
	"strconv"
	"testing"
	"time"

	_ "net/http/pprof"

	"github.com/stretchr/testify/require"
	_ "go.dedis.ch/dela/crypto"
	_ "go.dedis.ch/dela/dkg/pedersen/json"

	"go.dedis.ch/dela/mino/minogrpc"
	_ "go.dedis.ch/dela/mino/minogrpc"
	"go.dedis.ch/dela/mino/router/tree"

	"go.dedis.ch/dela/dkg"

	"go.dedis.ch/dela/mino"

	"go.dedis.ch/kyber/v3"

	"encoding/csv"
)

// func init() {
// 	rand.Seed(0)
// }

var nOldFlag = flag.String("nOld", "", "the number of old committee members")
var nCommonFlag = flag.String("nCommon", "", "the number of common members")
var nNewFlag = flag.String("nNew", "", "the number of new members")

// This test creats a dkg committee then creats another committee (that can
// share some nodes with the old committee) and then redistributes the secret to
// the new commitee. Using minogrpc as the underlying network
func TestResharingRecords(t *testing.T) {

	/////////////// managing the file
	file, err := os.OpenFile("resharing_records.csv", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	defer file.Close()
	if err != nil {
		log.Fatalln("failed to open file", err)
	}
	w := csv.NewWriter(file)

	// Setting up the first dkg

	nOld, err := strconv.Atoi(*nOldFlag)
	if err != nil {
		panic("not nOld right argument")
	}

	nCommon, err := strconv.Atoi(*nCommonFlag)
	if err != nil {
		panic("not nCommon right argument")
	}

	nNew, err := strconv.Atoi(*nNewFlag)
	if err != nil {
		panic("not nNew right argument")
	}
	// nOld := 3
	// nCommon := 3
	// nNew := 0
	/////////////////////////////////////////////////// first loop 	////////////////////////////////////////////
	//for _, nOld := range nOldSlice {
	fmt.Println("==============  starting the dkg ============== ")
	fmt.Println("n old = ", nOld)

	thresholdOld := nOld
	thresholdNew := nCommon + nNew
	/////////////////////////////////////////////////// second loop ////////////////////////////////////////////

	minosOld := make([]mino.Mino, nOld)
	dkgsOld := make([]dkg.DKG, nOld)
	addrsOld := make([]mino.Address, nOld)
	pubkeysOld := make([]kyber.Point, len(minosOld))

	// Defining the addresses
	for i := 0; i < nOld; i++ {
		addr := minogrpc.ParseAddress("127.0.0.1", 0)
		minogrpc, err := minogrpc.NewMinogrpc(addr, nil, tree.NewRouter(minogrpc.NewAddressFactory()))
		require.NoError(t, err)
		defer minogrpc.GracefulStop()

		minosOld[i] = minogrpc
		addrsOld[i] = minogrpc.GetAddress()
	}

	// Initializing the pedersen
	for i, mino := range minosOld {
		for _, m := range minosOld {
			mino.(*minogrpc.Minogrpc).GetCertificateStore().Store(m.GetAddress(), m.(*minogrpc.Minogrpc).GetCertificateChain())
		}

		dkg, pubkey := NewPedersen(mino.(*minogrpc.Minogrpc))

		dkgsOld[i] = dkg
		pubkeysOld[i] = pubkey
	}

	fakeAuthority := NewAuthority(addrsOld, pubkeysOld)

	// Initializing the old committee actors
	actorsOld := make([]dkg.Actor, nOld)

	for i := 0; i < nOld; i++ {
		actor, err := dkgsOld[i].Listen()
		require.NoError(t, err)
		actorsOld[i] = actor
	}

	start := time.Now()
	_, err = actorsOld[0].Setup(fakeAuthority, thresholdOld)
	dkgSetupTime := time.Since(start).Milliseconds()
	require.NoError(t, err, "setting up the firs dkg was not successful")

	// Encrypt a message with the old committee public key. the new committee
	// should be able to decrypt it successfully
	message := []byte("Hello world")
	K, C, remainder, err := actorsOld[0].Encrypt(message)
	require.NoError(t, err, "encrypting the message was not successful")
	require.Len(t, remainder, 0)

	minosNew := make([]mino.Mino, nNew+nCommon)
	dkgsNew := make([]dkg.DKG, nNew+nCommon)
	addrsNew := make([]mino.Address, nNew+nCommon)

	// The first nCommon nodes of  committee are the same as the first nCommon
	// nodes of the old committee
	for i := 0; i < nCommon; i++ {
		minosNew[i] = minosOld[i]
		addrsNew[i] = minosOld[i].GetAddress()
	}

	pubkeysNew := make([]kyber.Point, len(minosNew))

	// Defining the address of the new nodes.
	for i := 0; i < nNew; i++ {
		addr := minogrpc.ParseAddress("127.0.0.1", 0)
		minogrpc, err := minogrpc.NewMinogrpc(addr, nil, tree.NewRouter(minogrpc.NewAddressFactory()))
		require.NoError(t, err)
		defer minogrpc.GracefulStop()

		minosNew[i+nCommon] = minogrpc
		addrsNew[i+nCommon] = minogrpc.GetAddress()
	}

	// The first nCommon nodes of  committee are the same as the first nCommon
	// nodes of the old committee
	for i := 0; i < nCommon; i++ {
		dkgsNew[i] = dkgsOld[i]
		pubkeysNew[i] = pubkeysOld[i]
	}

	// Initializing the pedersen of the new nodes. the common nodes already have
	// a pedersen
	for i, mino := range minosNew {
		for _, m := range minosNew {
			mino.(*minogrpc.Minogrpc).GetCertificateStore().Store(m.GetAddress(), m.(*minogrpc.Minogrpc).GetCertificateChain())
			m.(*minogrpc.Minogrpc).GetCertificateStore().Store(mino.GetAddress(), mino.(*minogrpc.Minogrpc).GetCertificateChain())
		}
		for _, m := range minosOld {
			mino.(*minogrpc.Minogrpc).GetCertificateStore().Store(m.GetAddress(), m.(*minogrpc.Minogrpc).GetCertificateChain())
			m.(*minogrpc.Minogrpc).GetCertificateStore().Store(mino.GetAddress(), mino.(*minogrpc.Minogrpc).GetCertificateChain())
		}
		if i >= nCommon {
			dkg, pubkey := NewPedersen(mino.(*minogrpc.Minogrpc))
			dkgsNew[i] = dkg
			pubkeysNew[i] = pubkey

		}

	}

	// Initializing the actor of the new nodes. the common nodes already have an
	// actor
	actorsNew := make([]dkg.Actor, nNew+nCommon)

	for i := 0; i < nCommon; i++ {
		actorsNew[i] = actorsOld[i]
	}
	for i := 0; i < nNew; i++ {
		actor, err := dkgsNew[i+nCommon].Listen()
		require.NoError(t, err)
		actorsNew[i+nCommon] = actor
	}

	// Resharing the committee secret among the new committee
	fmt.Println("============== starting the resharing ==============")
	fakeAuthority = NewAuthority(addrsNew, pubkeysNew)
	start = time.Now()
	err = actorsOld[0].Reshare(fakeAuthority, thresholdNew)
	resharingTime := time.Since(start).Milliseconds()
	require.NoError(t, err, "Resharing was not successful")
	fmt.Println("==============  finishing the resharing ==============")
	// Comparing the public key of the old and the new committee
	oldPubKey, err := actorsOld[0].GetPublicKey()
	require.NoError(t, err)

	// fmt.Println("============== verifying the process ==============")

	for _, actorNew := range actorsNew {
		newPubKey, err := actorNew.GetPublicKey()

		// The public key should remain the same
		require.NoError(t, err, "the public key should remain the same")
		newPubKey.Equal(oldPubKey)
		decrypted, err := actorNew.Decrypt(K, C)
		require.NoError(t, err, "decryption was not successful")
		require.Equal(t, message, decrypted, "the new committee should be able to decrypt the messages encrypted by the old committee")
	}

	recordSlice := []string{strconv.Itoa(nOld), strconv.Itoa(nCommon), strconv.Itoa(nNew),
		strconv.Itoa(int(dkgSetupTime)), strconv.Itoa(int(resharingTime))}

	if err := w.Write(recordSlice); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	w.Flush()

}

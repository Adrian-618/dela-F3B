package pedersen

import (
	"encoding/csv"
	// "flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/dela/dkg"
	"go.dedis.ch/dela/mino"

	"go.dedis.ch/dela/mino/minogrpc"
	"go.dedis.ch/dela/mino/router/tree"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share/pvss"
)

func init() {
	rand.Seed(0)
}

// var nFlag = flag.String("n", "", "the number of committee members")

func Test_PVSS_records(t *testing.T) {
	// minoch is simulated communication, and grpc is more realistic and should be used here

	file, err := os.OpenFile("PVSS_records.csv", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	defer file.Close()
	if err != nil {
		log.Fatalln("failed to open file", err)
	}
	w := csv.NewWriter(file)

	n, err := strconv.Atoi(*nFlag)
	if err != nil {
		panic("not n right argument")
	}

	// setting up the dkg
	// n := 128
	threshold := n

	row := []string{strconv.Itoa(n)}

	minos := make([]mino.Mino, n)
	dkgs := make([]dkg.DKG, n)
	addrs := make([]mino.Address, n)

	// Here I wonder if we need the gbar for pvss. After all we don't run the DKG setup, maybe a random generator is fine?
	agreedData := make([]byte, 32)
	_, err = rand.Read(agreedData)
	require.NoError(t, err)

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

	fmt.Printf("setting up the dkg ...")
	start := time.Now()
	_, err = actors[0].Setup(fakeAuthority, threshold)
	require.NoError(t, err)
	setupTime := time.Since(start)
	//This setup time should be much smaller than DKG setup time

	// here we dont need batch
	fmt.Printf("generaing the encrypted key shares ...")

	start = time.Now()
	shares, pubpoly, h, symkey, err := actors[0].RunPVSS(n, threshold, fakeAuthority)
	encryptTime := time.Since(start).Milliseconds()
	// fmt.Println("encrypt time is: ", encryptTime)
	shared := suite.Point().Mul(symkey, nil)
	buf, err := deriveKey(shared)
	enckey := buf[:KEY_LENGTH]
	// fmt.Println("enckey", enckey)
	//I want to calculate the data size of the shares, and pubpoly
	fmt.Println("shares size is: ", len(shares))
	fmt.Println("shares size is: ", *shares[0])
	// fmt.Println("pubpoly size is: ", len(pubboly))

	fakebatchShares := [][]*pvss.PubVerShare{shares} // change codes later to just remove the batch
	fmt.Printf("decrypting the key shares ...")
	start = time.Now()
	decKey, rcvTime, decTime, err := actors[0].DecPVSS(h, pubpoly, fakebatchShares)
	decryptionTime := time.Since(start).Milliseconds()
	require.NoError(t, err)

	require.Equal(t, enckey, decKey[0])
	row = append(row, strconv.Itoa(int(encryptTime)))
	row = append(row, strconv.Itoa(int(rcvTime)))
	row = append(row, strconv.Itoa(int(decTime)))
	row = append(row, strconv.Itoa(int(decryptionTime)))

	if err := w.Write(row); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	w.Flush()

	fmt.Printf("n=%d, encryption time=%d, decryption time=%d, "+
		"setup time=%s, rcvTime=%d, decTime=%d", n, encryptTime,
		decryptionTime, setupTime, rcvTime, decTime)
}

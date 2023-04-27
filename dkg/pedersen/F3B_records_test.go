package pedersen

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/dela/dkg"
	"go.dedis.ch/dela/dkg/pedersen/types"
	"go.dedis.ch/dela/mino"

	"go.dedis.ch/dela/mino/minogrpc"
	"go.dedis.ch/dela/mino/router/tree"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/xof/keccak"
)

var nFlag = flag.String("n", "", "the number of committee members")

func Test_F3B_records(t *testing.T) {

	file, err := os.OpenFile("F3B_records.csv", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	defer file.Close()
	if err != nil {
		log.Fatalln("failed to open file", err)
	}
	w := csv.NewWriter(file)

	n, err := strconv.Atoi(*nFlag)
	if err != nil {
		panic("not n right argument")
	}

	// we want to time the decryption for different batch sizes with different number of nodes
	// numWorkersSlice := []int{16, 16, 32, 64, 64, 64, 64}
	// batchSizeSlice := []int{32, 64, 128, 256, 512, 1024, 2048}
	batchSizeSlice := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}

	///////////////////////////////////////////////////////// the main loop
	//for _ ,n := range(nSlice){
	threshold := n

	row := []string{strconv.Itoa(n)}

	minos := make([]mino.Mino, n)
	dkgs := make([]dkg.DKG, n)
	addrs := make([]mino.Address, n)

	// creating GBar. we need a generator in order to follow the encryption and decryption protocol of https://arxiv.org/pdf/2205.08529.pdf /
	// we take an agreed data among the participants and embed it as a point. the result is the generator that we are seeking
	agreedData := make([]byte, 32)
	_, err = rand.Read(agreedData)
	require.NoError(t, err)
	GBar := suite.Point().Embed(agreedData, keccak.New(agreedData))

	fmt.Println("initiating the dkg nodes ...")
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
			mino.(*minogrpc.Minogrpc).GetCertificateStore().Store(m.GetAddress(), m.(*minogrpc.Minogrpc).GetCertificateChain())
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

	fmt.Println("setting up the dkg ...")
	_, err = actors[0].Setup(fakeAuthority, threshold)
	require.NoError(t, err)

	//generating random messages in batch and encrypt them
	for _, batchSize := range batchSizeSlice {
		fmt.Printf("=== starting the process with batch size = %d === \n", batchSize)

		const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		keys := make([][]byte, batchSize)
		var ciphertexts []types.Ciphertext
		for i := 0; i < batchSize; i++ {
			keys[i] = make([]byte, 29)
			for j := range keys[i] {
				keys[i][j] = letterBytes[rand.Intn(len(letterBytes))]
			}
			ciphertext, remainder, err := actors[0].VerifiableEncrypt(keys[i], GBar)
			require.NoError(t, err)
			require.Len(t, remainder, 0)
			ciphertexts = append(ciphertexts, ciphertext)
		}
		// decryopting the batch ciphertext message
		fmt.Println("decrypting the batch ...")
		_, recieveSharesTime, decryptionTime, err := actors[0].VerifiableDecrypt(ciphertexts)
		require.NoError(t, err)
		row = append(row, strconv.Itoa(int(recieveSharesTime)))
		row = append(row, strconv.Itoa(int(decryptionTime)))
	}

	if err := w.Write(row); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	w.Flush()
	//}
}

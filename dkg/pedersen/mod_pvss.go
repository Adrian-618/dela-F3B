package pedersen

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/share/pvss"
	"go.dedis.ch/kyber/v3/suites"
	"golang.org/x/crypto/hkdf"
)

const KEY_LENGTH = 32
const LENGTH = KEY_LENGTH + 12

func Encrypt_test(suite suites.Suite, secret kyber.Scalar, mesg []byte) ([]byte,
	[]byte, error) {
	shared := suite.Point().Mul(secret, nil)
	buf, err := deriveKey(shared)
	key := buf[:KEY_LENGTH]
	fmt.Println("enc_key: ", key)
	nonce := buf[KEY_LENGTH:LENGTH]

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, nil, err
	}
	ctxt := aesgcm.Seal(nil, nonce, mesg, nil)
	ctxtHash := sha256.Sum256(ctxt)
	return ctxt, ctxtHash[:], nil
}

func Decrypt_test(shared kyber.Point, ctxt []byte) ([]byte, error) {
	buf, err := deriveKey(shared)
	if err != nil {
		return nil, err
	}
	key := buf[:32]
	fmt.Println("dec_key: ", key)
	nonce := buf[32:LENGTH]
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(aes)
	return aesgcm.Open(nil, nonce, ctxt, nil)
}

func deriveKey(shared kyber.Point) ([]byte, error) {
	hash := sha256.New
	sb, err := shared.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hkdf := hkdf.New(hash, sb, nil, nil)
	key := make([]byte, LENGTH, LENGTH)
	n, err := hkdf.Read(key)
	if err != nil {
		return nil, err
	}
	if n < LENGTH {
		return nil, errors.New("HKDF-derived key too short")
	}
	return key, nil
}

// this is a test function for the PVSS_test to use. First I need to make sure that I can indeed recover the secret from the shares.
func RecoverSecret_test(suite suites.Suite, G kyber.Point, X []kyber.Point, encShares []*pvss.PubVerShare, decShares []*pvss.PubVerShare, t int, n int) (kyber.Point, error) {
	D, err := pvss.VerifyDecShareBatch(suite, G, X, encShares, decShares)
	if err != nil {
		return nil, err
	}
	if len(D) < t {
		fmt.Println(len(D), t)
		return nil, fmt.Errorf("not enough valid decryption shares")
	}
	var shares []*share.PubShare
	for _, s := range D {
		shares = append(shares, &s.S)
	}
	return share.RecoverCommit(suite, shares, t, n)
}

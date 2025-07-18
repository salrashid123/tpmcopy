package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath  = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	pemFile  = flag.String("pemFile", "/tmp/tpmkey.pem", "KeyFile in PEM format")
	password = flag.String("password", "", "Password authorization value")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}
func main() {
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {

	flag.Parse()

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	c, err := os.ReadFile(*pemFile)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// create a new session to load
	load_session, load_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer load_session_cleanup()

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		PolicySession: load_session.Handle(),
		NonceTPM:      load_session.NonceTPM(),
	}.Execute(rwr)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	rsaKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   load_session,
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	sign := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: rsaKey.ObjectHandle,
			Name:   rsaKey.Name,
			Auth:   tpm2.PasswordAuth([]byte(*password)),
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	eccSign, err := sign.Execute(rwr)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	ecs, err := eccSign.Signature.Signature.ECDSA()
	if err != nil {
		fmt.Println(err)
		return 1
	}
	log.Printf("signature: R %s\n", base64.StdEncoding.EncodeToString(ecs.SignatureR.Buffer))
	log.Printf("signature: S %s\n", base64.StdEncoding.EncodeToString(ecs.SignatureS.Buffer))

	x := big.NewInt(0).SetBytes(ecs.SignatureR.Buffer)
	y := big.NewInt(0).SetBytes(ecs.SignatureS.Buffer)

	ppub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMIDHObject(rsaKey.ObjectHandle),
	}.Execute(rwr)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	outPub, err := ppub.OutPublic.Contents()
	if err != nil {
		fmt.Println(err)
		return 1
	}

	ecDetail, err := outPub.Parameters.ECCDetail()
	if err != nil {
		fmt.Println(err)
		return 1
	}
	crv, err := ecDetail.CurveID.Curve()
	if err != nil {
		fmt.Println(err)
		return 1
	}

	eccUnique, err := outPub.Unique.ECC()
	if err != nil {
		fmt.Println(err)
		return 1
	}

	pubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	ok := ecdsa.Verify(pubKey, digest[:], x, y)
	if !ok {
		fmt.Println(err)
		return 1
	}

	fmt.Println("signature verified")

	return 0
}

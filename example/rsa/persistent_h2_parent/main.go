package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	tpmcopy "github.com/salrashid123/tpmcopy"
)

// sample to show how to initialize and use the key if the parent is referenced as
// a persistent handle

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

	h2primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {

		fmt.Println(err)
		return 1
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: h2primary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: h2primary.ObjectHandle,
			Name:   h2primary.Name,
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

	// construct the policy using the utility in this library
	tc, err := tpmcopy.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(*password), h2primary.Name, h2primary.ObjectHandle)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	or_sess, or_cleanup, err := tc.GetSession()
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer or_cleanup()

	sign := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: rsaKey.ObjectHandle,
			Name:   rsaKey.Name,
			Auth:   or_sess,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rspSign, err := sign.Execute(rwr)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	rsassa, err := rspSign.Signature.Signature.RSASSA()
	if err != nil {
		fmt.Println(err)
		return 1
	}

	fmt.Printf("signature: %s\n", hex.EncodeToString(rsassa.Sig.Buffer))

	return 0
}

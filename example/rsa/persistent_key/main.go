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

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	tpmcopy "github.com/salrashid123/tpmcopy"
)

const ()

var (
	tpmPath          = flag.String("tpm-path", "127.0.0.1:2341", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81018001, "PersistnetHandle to use  in PEM format")
	password         = flag.String("password", "", "Password authorization value")
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

	pubregen, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMIDHObject(tpm2.TPMHandle(*persistentHandle).HandleValue()),
	}.Execute(rwr)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	// create a new session to load
	// load_session, load_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }
	// defer load_session_cleanup()

	// _, err = tpm2.PolicySecret{
	// 	AuthHandle: tpm2.AuthHandle{
	// 		Handle: tpm2.TPMRHEndorsement,
	// 		Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
	// 		Auth:   tpm2.PasswordAuth([]byte("")),
	// 	},
	// 	PolicySession: load_session.Handle(),
	// 	NonceTPM:      load_session.NonceTPM(),
	// }.Execute(rwr)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }

	// rsaKey, err := tpm2.Load{
	// 	ParentHandle: tpm2.AuthHandle{
	// 		Handle: primaryKey.ObjectHandle,
	// 		Name:   tpm2.TPM2BName(primaryKey.Name),
	// 		Auth:   load_session,
	// 	},
	// 	InPublic:  pubregen.OutPublic,
	// 	InPrivate: key.Privkey,
	// }.Execute(rwr)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }

	// defer func() {
	// 	flushContextCmd := tpm2.FlushContext{
	// 		FlushHandle: rsaKey.ObjectHandle,
	// 	}
	// 	_, _ = flushContextCmd.Execute(rwr)
	// }()

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	// construct the policy using the utility in this library
	tc, err := tpmcopy.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(*password), primaryKey.Name, primaryKey.ObjectHandle)
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
			Handle: tpm2.TPMIDHObject(tpm2.TPMHandle(*persistentHandle).HandleValue()),
			Name:   pubregen.Name,
			Auth:   or_sess, // tpm2.PasswordAuth([]byte(*password)),
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

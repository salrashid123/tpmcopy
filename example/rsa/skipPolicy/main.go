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
)

const ()

var (
	tpmPath       = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	pemFile       = flag.String("pemFile", "/tmp/tpmkey.pem", "KeyFile in PEM format")
	parentkeyType = flag.String("parentKeyType", "rsa_ek", "type of of the parent key (rsa or ecc)")
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

	var pubK tpm2.TPMTPublic
	var parent tpm2.TPMHandle
	switch *parentkeyType {
	case "ecc_ek":
		pubK = tpm2.ECCEKTemplate
		parent = tpm2.TPMRHEndorsement
	case "rsa_ek":
		pubK = tpm2.RSAEKTemplate
		parent = tpm2.TPMRHEndorsement
	case "h2":
		pubK = keyfile.ECCSRK_H2_Template
		parent = tpm2.TPMRHOwner
	default:
		fmt.Println("unknown parent key type")
		return 1
	}

	var rsaKey *tpm2.LoadResponse

	if *parentkeyType == "h2" {
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
		rsaKey, err = tpm2.Load{
			ParentHandle: tpm2.NamedHandle{
				Handle: h2primary.ObjectHandle,
				Name:   tpm2.TPM2BName(h2primary.Name),
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

	} else {
		primaryKey, err := tpm2.CreatePrimary{
			PrimaryHandle: parent,
			InPublic:      tpm2.New2B(pubK),
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

		rsaKey, err = tpm2.Load{
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
	}

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	// pa_sess, pa_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(nil))}...)
	// if err != nil {
	// 	return 1
	// }

	// _, err = tpm2.PolicyAuthValue{
	// 	PolicySession: pa_sess.Handle(),
	// }.Execute(rwr)
	// if err != nil {
	// 	return 1
	// }

	// defer pa_cleanup()

	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: rsaKey.ObjectHandle,
			Name:   rsaKey.Name,
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

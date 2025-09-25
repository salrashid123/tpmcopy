package main

import (
	"crypto/aes"
	"crypto/rand"
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
	genkeyutil "github.com/salrashid123/tpm2genkey/util"
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

	if !key.EmptyAuth && *password == "" {
		log.Fatalf("password must be provided if key has non null emptyAuth ")
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

	aesKey, err := tpm2.Load{
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
			FlushHandle: aesKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	data := []byte(stringToSign)

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		log.Fatalf("can't read rsa details %q: %v", *tpmPath, err)
	}

	// construct the policy using the utility in this library

	or_sesse, or_cleanupe, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(*password))}...)

	if err != nil {
		return 1
	}
	defer or_cleanupe()

	for _, ppol := range key.Policy {
		switch cc := ppol.CommandCode; cc {
		case int(tpm2.TPMCCPolicyAuthValue):

			policy := &tpm2.PolicyAuthValue{
				PolicySession: or_sesse.Handle(),
			}

			err = genkeyutil.ReqParameters(ppol.CommandPolicy, policy)
			if err != nil {
				log.Fatalf("setting up PolicyAuthValue: %v", err)
			}
			_, err = policy.Execute(rwr)
			if err != nil {
				log.Fatalf("setting up PolicyAuthValue: %v", err)
			}
		case int(tpm2.TPMCCPolicyPCR):

			policy := &tpm2.PolicyPCR{
				PolicySession: or_sesse.Handle(),
			}

			err = genkeyutil.ReqParameters(ppol.CommandPolicy, policy)
			if err != nil {
				log.Fatalf("setting up PolicyPCR: %v", err)
			}
			_, err = policy.Execute(rwr)
			if err != nil {
				log.Fatalf("setting up PolicyPCR: %v", err)
			}
		case int(tpm2.TPMCCPolicyDuplicationSelect):

			// policy := &tpm2.PolicyDuplicationSelect{
			// 	PolicySession: or_sesse.Handle(),
			// }

			// err = genkeyutil.ReqParameters(ppol.CommandPolicy, policy)
			// if err != nil {
			// 	log.Fatalf("setting up PolicyDuplicationSelect: %v", err)
			// }
			// _, err = policy.Execute(rwr)
			// if err != nil {
			// 	log.Fatalf("setting up PolicyDuplicationSelect: %v", err)
			// }
		case int(tpm2.TPMCCPolicyOR):

			policy := &tpm2.PolicyOr{
				PolicySession: or_sesse.Handle(),
			}

			err = genkeyutil.ReqParameters(ppol.CommandPolicy, policy)
			if err != nil {
				log.Fatalf("setting up PolicyOr: %v", err)
			}

			_, err = policy.Execute(rwr)
			if err != nil {
				log.Fatalf("setting up PolicyOr: %v", err)
			}

		default:

		}
	}

	keyAuth := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   or_sesse,
	}
	encrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, data, false)
	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}
	err = or_cleanupe()
	if err != nil {
		return 1
	}
	log.Printf("IV: %s", hex.EncodeToString(iv))
	log.Printf("Encrypted %s", hex.EncodeToString(encrypted))

	or_sessd, or_cleanupd, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(*password))}...)

	if err != nil {
		return 1
	}
	defer or_cleanupd()

	for _, ppol := range key.Policy {
		switch cc := ppol.CommandCode; cc {
		case int(tpm2.TPMCCPolicyAuthValue):

			policy := &tpm2.PolicyAuthValue{
				PolicySession: or_sessd.Handle(),
			}

			err = genkeyutil.ReqParameters(ppol.CommandPolicy, policy)
			if err != nil {
				log.Fatalf("setting up PolicyAuthValue: %v", err)
			}
			_, err = policy.Execute(rwr)
			if err != nil {
				log.Fatalf("setting up PolicyAuthValue: %v", err)
			}
		case int(tpm2.TPMCCPolicyPCR):

			policy := &tpm2.PolicyPCR{
				PolicySession: or_sessd.Handle(),
			}

			err = genkeyutil.ReqParameters(ppol.CommandPolicy, policy)
			if err != nil {
				log.Fatalf("setting up PolicyPCR: %v", err)
			}
			_, err = policy.Execute(rwr)
			if err != nil {
				log.Fatalf("setting up PolicyPCR: %v", err)
			}
		case int(tpm2.TPMCCPolicyDuplicationSelect):

			// policy := &tpm2.PolicyDuplicationSelect{
			// 	PolicySession: or_sessd.Handle(),
			// }

			// err = genkeyutil.ReqParameters(ppol.CommandPolicy, policy)
			// if err != nil {
			// 	log.Fatalf("setting up PolicyDuplicationSelect: %v", err)
			// }
			// _, err = policy.Execute(rwr)
			// if err != nil {
			// 	log.Fatalf("setting up PolicyDuplicationSelect: %v", err)
			// }

		case int(tpm2.TPMCCPolicyOR):

			policy := &tpm2.PolicyOr{
				PolicySession: or_sessd.Handle(),
			}

			err = genkeyutil.ReqParameters(ppol.CommandPolicy, policy)
			if err != nil {
				log.Fatalf("setting up PolicyOr: %v", err)
			}

			_, err = policy.Execute(rwr)
			if err != nil {
				log.Fatalf("setting up PolicyOr: %v", err)
			}

		default:

		}
	}

	keyAuth = tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   or_sessd, // tpm2.PasswordAuth([]byte(*password)),
	}

	decrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, encrypted, true)
	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}

	log.Printf("Decrypted by TPM %s", string(decrypted))

	// ***********************************

	return 0
}

const maxDigestBuffer = 1024

func encryptDecryptSymmetric(rwr transport.TPM, keyAuth tpm2.AuthHandle, iv, data []byte, decrypt bool) ([]byte, error) {
	var out, block []byte

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: keyAuth,
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    tpm2.TPMAlgCFB,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
}

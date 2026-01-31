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
	tpmcopy "github.com/salrashid123/tpmcopy"
)

const ()

var (
	tpmPath       = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	pemFile       = flag.String("pemFile", "/tmp/tpmkey.pem", "KeyFile in PEM format")
	ownerPassword = flag.String("ownerPassword", "", "Password authorization for the owher")
	password      = flag.String("password", "", "Password authorization value")
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

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
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

	aesKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth([]byte(*ownerPassword)),
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
	tce, err := tpmcopy.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(*password), primaryKey.Name, primaryKey.ObjectHandle)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	or_sesse, or_cleanupe, err := tce.GetSession()
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer or_cleanupe()

	keyAuth := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   or_sesse, // tpm2.PasswordAuth([]byte(*password)),
	}
	encrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, data, false)

	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}
	log.Printf("IV: %s", hex.EncodeToString(iv))
	log.Printf("Encrypted %s", hex.EncodeToString(encrypted))

	// construct the policy using the utility in this library
	tcd, err := tpmcopy.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(*password), primaryKey.Name, primaryKey.ObjectHandle)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	or_sessd, or_cleanupd, err := tcd.GetSession()
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer or_cleanupd()

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

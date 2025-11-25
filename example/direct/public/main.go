package main

import (
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
	"github.com/salrashid123/tpmcopy"
)

const ()

var (
	tpmPath          = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	tpmPublicKeyFile = flag.String("tpmPublicKeyFile", "/tmp/public.pem", "ParentKey in PEM format")
	ownerpw          = flag.String("ownerpw", "", "Owner Password for the created key")
	parentKeyType    = flag.String("parentKeyType", "rsa_ek", "rsa_ek|ecc_ek|h2 (default rsa_ek)")
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

	var t tpm2.TPMTPublic
	var primaryHandle tpm2.TPMHandle

	switch *parentKeyType {
	case tpmcopy.RSA_EK:
		t = tpm2.RSAEKTemplate
		primaryHandle = tpm2.TPMRHEndorsement
	case tpmcopy.ECC_EK:
		t = tpm2.ECCEKTemplate
		primaryHandle = tpm2.TPMRHEndorsement
	case tpmcopy.H2:
		t = keyfile.ECCSRK_H2_Template
		primaryHandle = tpm2.TPMRHOwner
	default:
		fmt.Fprintf(os.Stderr, "unsupported --parentKeyType must be either rsa or ecc, got %v\n", *parentKeyType)
		return 1
	}

	cCreateEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: primaryHandle,
			Name:   tpm2.HandleName(primaryHandle),
			Auth:   tpm2.PasswordAuth([]byte(*ownerpw)),
		},
		InPublic: tpm2.New2B(t),
	}.Execute(rwr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't create object TPM: %v", err)
		return 1
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cCreateEK.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't close TPM %v", err)
		}
	}()

	b, err := tpmcopy.GetPublicKey(&tpmcopy.TPMConfig{
		TPMDevice: rwc,
		Ownerpw:   []byte(*ownerpw),
	}, cCreateEK.ObjectHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't getting public key %v", err)
		return 1
	}

	err = os.WriteFile(*tpmPublicKeyFile, b, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing public key to file %v\n", err)
		return 1
	}

	fmt.Printf("%s\n", string(b))
	fmt.Printf("Public Key written to: %s\n", *tpmPublicKeyFile)

	return 0
}

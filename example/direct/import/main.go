package main

import (
	"bytes"
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
	duplicatepb "github.com/salrashid123/tpmcopy/duplicatepb"
	"google.golang.org/protobuf/encoding/protojson"
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	ownerpw = flag.String("ownerpw", "", "Owner Password for the created key")

	in            = flag.String("in", "/tmp/out.json", "FileName with the key to import")
	out           = flag.String("out", "/tmp/key.pem", "File to write the duplicate to")
	pubout        = flag.String("pubout", "/tmp/pub.bin", "(optional) File to write the tpm2_tools compatible public part")
	privout       = flag.String("privout", "/tmp/priv.bin", "(optional) File to write the tpm2_tools compatible private part")
	parentKeyType = flag.String("parentKeyType", "rsa_ek", "rsa_ek|ecc_ek|h2 (default rsa_ek)")

	password               = flag.String("password", "", "Password for the created key")
	parentpersistentHandle = flag.Uint("parentpersistentHandle", 0, "persistentHandle to save the key to (default 0 persistent)")
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

	if *in == "" || *out == "" {
		fmt.Fprintf(os.Stderr, "in and out  parameters must be specified")
		return 1
	}

	bt, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing reading blob %v\n", err)
		return 1
	}

	sessionEncryptionRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth([]byte(*ownerpw)),
		},
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating EK Primary  %v", err)
		return 1
	}
	defer func() {
		_, _ = tpm2.FlushContext{
			FlushHandle: sessionEncryptionRsp.ObjectHandle,
		}.Execute(rwr)
	}()

	var k duplicatepb.Secret

	err = protojson.Unmarshal(bt, &k)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to unmarshall proto Key: %v", err)
		return 1
	}

	var t tpm2.TPMTPublic

	if *parentKeyType == tpmcopy.RSA_EK && k.ParentKeyType == duplicatepb.Secret_EndorsementRSA {
		t = tpm2.RSAEKTemplate
	} else if *parentKeyType == tpmcopy.ECC_EK && k.ParentKeyType == duplicatepb.Secret_EndoresementECC {
		t = tpm2.ECCEKTemplate
	} else if *parentKeyType == tpmcopy.H2 && k.ParentKeyType == duplicatepb.Secret_H2 {
		t = keyfile.ECCSRK_H2_Template
	} else {
		fmt.Fprintf(os.Stderr, "  keytype in file [%s] mismatched with command line: [%s]", k.ParentKeyType, *parentKeyType)
		return 1
	}

	var primaryParent tpm2.TPMHandle

	if k.ParentKeyType == duplicatepb.Secret_H2 {
		primaryParent = tpm2.TPMRHOwner
	} else {
		primaryParent = tpm2.TPMRHEndorsement
	}

	cCreateEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: primaryParent,
			Name:   tpm2.HandleName(primaryParent),
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
			fmt.Fprintf(os.Stderr, "can't closing ek %v", err)
		}
	}()

	parentHandle := cCreateEK.ObjectHandle

	tpmKey, err := tpmcopy.Import(&tpmcopy.TPMConfig{
		TPMDevice:               rwc,
		Ownerpw:                 []byte(*ownerpw),
		SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle}, parentHandle, k)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to import Key: %v", err)
		return 1
	}
	kfb := new(bytes.Buffer)

	if keyfile.IsMSO(tpm2.TPMHandle(*parentpersistentHandle), keyfile.TPM_HT_PERSISTENT) {
		tpmKey.Parent = tpm2.TPMHandle(*parentpersistentHandle)
	}

	err = keyfile.Encode(kfb, &tpmKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing public key to file %v\n", err)
		return 1
	}

	err = os.WriteFile(*out, kfb.Bytes(), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing public key to file %v\n", err)
		return 1
	}

	if *pubout != "" {
		f := tpm2.Marshal(tpmKey.Pubkey)
		err = os.WriteFile(*pubout, f, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing public key to file %v\n", err)
			return 1
		}
	}
	if *privout != "" {
		f := tpm2.Marshal(tpmKey.Privkey)
		err = os.WriteFile(*privout, f, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing public key to file %v\n", err)
			return 1
		}
	}

	fmt.Printf("Imported Key written to: %s\n", *out)

	return 0
}

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	saltpm "github.com/salrashid123/signer/tpm"
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	pemFile = flag.String("pemFile", "/tmp/tpmkey.pem", "KeyFile in PEM format")
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

	se, err := NewPCRAndDuplicateSelectSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uint(23)),
		},
	}, nil, primaryKey.Name)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		NamedHandle: &tpm2.NamedHandle{
			Handle: rsaKey.ObjectHandle,
			Name:   rsaKey.Name,
		},
		AuthSession: se,
	})
	if err != nil {
		fmt.Println(err)
		return 1
	}

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		return 1
	}
	fmt.Printf("RSA Signed String: %s\n", base64.StdEncoding.EncodeToString(s))

	rsaPubKey, ok := r.Public().(*rsa.PublicKey)
	if !ok {
		fmt.Println(err)
		return 1
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest, s)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	fmt.Printf("RSA Signed String verified\n")

	return 0
}

// ***************

type MyPCRAndDuplicateSelectSession struct {
	_        saltpm.Session
	rwr      transport.TPM
	sel      []tpm2.TPMSPCRSelection
	password []byte
	ekName   tpm2.TPM2BName
}

func NewPCRAndDuplicateSelectSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, password []byte, ekName tpm2.TPM2BName) (MyPCRAndDuplicateSelectSession, error) {
	return MyPCRAndDuplicateSelectSession{nil, rwr, sel, password, ekName}, nil
}

func (p MyPCRAndDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	// var options []tpm2.AuthOption
	// options = append(options, tpm2.Auth(p.password))

	pcr_sess, pcr_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: pcr_sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	pcrpgd, err := tpm2.PolicyGetDigest{
		PolicySession: pcr_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = pcr_cleanup()
	if err != nil {
		return nil, nil, err
	}

	// create another real session with the PolicyDuplicationSelect and remember to specify the EK
	// as the "new parent"
	dupselect_sess, dupselect_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: p.ekName,
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}

	// now create an OR session with the two above policies above
	or_sess, or_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	//defer or_cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: or_sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	return or_sess, or_cleanup, nil
}

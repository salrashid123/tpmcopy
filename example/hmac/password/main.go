package main

import (
	"encoding/hex"
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
	tpmcopy "github.com/salrashid123/tpmcopy"
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

	hmacKey, err := tpm2.Load{
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
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	data := []byte(stringToSign)

	objAuth := &tpm2.TPM2BAuth{
		Buffer: []byte(*password),
	}

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

	/// **or do it manually
	// pa_sess, pa_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	// if err != nil {
	// 	return 1
	// }
	// defer pa_cleanup()

	// _, err = tpm2.PolicyAuthValue{
	// 	PolicySession: pa_sess.Handle(),
	// }.Execute(rwr)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }

	// papgd, err := tpm2.PolicyGetDigest{
	// 	PolicySession: pa_sess.Handle(),
	// }.Execute(rwr)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }
	// err = pa_cleanup()
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }

	// // as the "new parent"
	// dupselect_sess, dupselect_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }
	// defer dupselect_cleanup()

	// _, err = tpm2.PolicyDuplicationSelect{
	// 	PolicySession: dupselect_sess.Handle(),
	// 	NewParentName: primaryKey.Name,
	// }.Execute(rwr)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }

	// // calculate the digest
	// dupselpgd, err := tpm2.PolicyGetDigest{
	// 	PolicySession: dupselect_sess.Handle(),
	// }.Execute(rwr)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }
	// err = dupselect_cleanup()
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }

	// // now create an OR session with the two above policies above

	// //or_sess, or_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)

	// or_sess, or_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(*password))}...)

	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }
	// defer or_cleanup()

	// _, err = tpm2.PolicyAuthValue{
	// 	PolicySession: or_sess.Handle(),
	// }.Execute(rwr)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }

	// _, err = tpm2.PolicyOr{
	// 	PolicySession: or_sess.Handle(),
	// 	PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{papgd.PolicyDigest, dupselpgd.PolicyDigest}},
	// }.Execute(rwr)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 1
	// }

	hmacBytes, err := hmac(rwr, data, hmacKey.ObjectHandle, hmacKey.Name, or_sess, *objAuth) //*objAuth)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	log.Printf("Hmac: %s\n", hex.EncodeToString(hmacBytes))

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	return 0
}

const (
	maxInputBuffer = 1024
)

// func hmac(rwr transport.TPM, data []byte, objHandle tpm2.TPMHandle, objName tpm2.TPM2BName, objAuth tpm2.TPM2BAuth) ([]byte, error) {
func hmac(rwr transport.TPM, data []byte, objHandle tpm2.TPMHandle, objName tpm2.TPM2BName, or_sess tpm2.Session, objAuth tpm2.TPM2BAuth) ([]byte, error) {

	sas, sasCloser, err := tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(objAuth.Buffer))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = sasCloser()
	}()

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: sas.Handle(),
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	hmacStart := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: objHandle,
			Name:   objName,
			Auth:   or_sess, // sas,
		},
		Auth:    objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}

	rspHS, err := hmacStart.Execute(rwr)
	if err != nil {
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   objName,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			return nil, err
		}

		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		return nil, err
	}

	return rspSC.Result.Buffer, nil

}

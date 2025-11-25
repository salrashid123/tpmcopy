package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/tpmcopy"
	duplicatepb "github.com/salrashid123/tpmcopy/duplicatepb"
	"google.golang.org/protobuf/encoding/protojson"
)

const ()

var (
	tpmPath          = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	tpmPublicKeyFile = flag.String("tpmPublicKeyFile", "/tmp/public.pem", "ParentKey in PEM format")
	ownerpw          = flag.String("ownerpw", "", "Owner Password for the created key")
	parentKeyType    = flag.String("parentKeyType", "rsa_ek", "rsa_ek|ecc_ek|h2 (default rsa_ek)")
	secret           = flag.String("secret", "/tmp/hmac_256.key", "File with secret to duplicate (rsa | ecc | hex encoded symmetric key or hmac pass)")
	out              = flag.String("out", "/tmp/out.json", "File to write the duplicate to")

	hashScheme = flag.String("hashScheme", "sha256", "sha256|sha384|sha512 (default sha256)")
	keyName    = flag.String("keyName", "", "User defined description of the key to export")

	password = flag.String("password", "", "Password for the created key")
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

	if *tpmPublicKeyFile == "" || *secret == "" || *out == "" {
		fmt.Fprintf(os.Stderr, "tpmPublicKeyFile, secret and out  parameters must be specified")
		return 1
	}

	ep, err := os.ReadFile(*tpmPublicKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return 1
	}

	var ekPububFromPEMTemplate tpm2.TPMTPublic
	block, _ := pem.Decode(ep)
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return 1
	}
	var pkt duplicatepb.Secret_ParentKeyType
	switch pub := parsedKey.(type) {
	case *rsa.PublicKey:
		rsaPub, ok := parsedKey.(*rsa.PublicKey)
		if !ok {
			fmt.Fprintf(os.Stderr, "  error converting encryptingPublicKey to rsa")
			return 1
		}
		ekPububFromPEMTemplate = tpm2.RSAEKTemplate
		pkt = duplicatepb.Secret_EndorsementRSA
		ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: rsaPub.N.Bytes(),
			},
		)
	case *ecdsa.PublicKey:
		ecPub, ok := parsedKey.(*ecdsa.PublicKey)
		if !ok {
			fmt.Fprintf(os.Stderr, "  error converting encryptingPublicKey to ecdsa")
			return 1
		}

		if *parentKeyType == tpmcopy.H2 {
			ekPububFromPEMTemplate = keyfile.ECCSRK_H2_Template
			pkt = duplicatepb.Secret_H2
		} else {
			ekPububFromPEMTemplate = tpm2.ECCEKTemplate
			pkt = duplicatepb.Secret_EndoresementECC
		}
		ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: ecPub.X.Bytes(),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: ecPub.Y.Bytes(),
				},
			},
		)
	default:
		fmt.Fprintf(os.Stderr, "unsupported public key type %v", pub)
		return 1
	}

	// now read in the secret
	f, err := os.ReadFile(*secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading secret : %v", err)
		return 1
	}

	var hsh tpm2.TPMAlgID
	switch *hashScheme {
	case "sha256":
		hsh = tpm2.TPMAlgSHA256
	case "sha384":
		hsh = tpm2.TPMAlgSHA384
	case "sha512":
		hsh = tpm2.TPMAlgSHA512
	default:
		fmt.Fprintf(os.Stderr, " unknown hash selected %s", *hashScheme)
		return 1
	}

	var dupKeyTemplate tpm2.TPMTPublic
	var sens2B tpm2.TPMTSensitive
	var kt duplicatepb.Secret_KeyType

	keySensitive := f
	hh, err := hsh.Hash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error converting hash: %v", err)
		return 1
	}

	// hmac is bound by the block size (openssl wraps larger keys to fit in)
	if len(keySensitive) > hh.New().BlockSize() {
		fmt.Fprintf(os.Stderr, "error max hmac key size is %d bytes", sha256.BlockSize)
		return 1
	}

	sv := make([]byte, 32)
	io.ReadFull(rand.Reader, sv)
	privHash := crypto.SHA256.New()
	privHash.Write(sv)
	privHash.Write(keySensitive)
	kt = duplicatepb.Secret_HMAC

	dupKeyTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        false,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{
							HashAlg: hsh,
						}),
				},
			}),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BDigest{
				Buffer: privHash.Sum(nil),
			},
		),
	}

	sens2B = tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue: tpm2.TPM2BDigest{
			Buffer: sv,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BSensitiveData{Buffer: keySensitive},
		),
	}

	if *password != "" {
		sens2B.AuthValue = tpm2.TPM2BAuth{
			Buffer: []byte(*password), // set any userAuth
		}
	}
	wrappb, err := tpmcopy.Duplicate(ekPububFromPEMTemplate, kt, pkt, *keyName, dupKeyTemplate, sens2B, make(map[uint][]byte))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error duplicating %v", err)
		return 1
	}

	b, err := protojson.Marshal(&wrappb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to wrap proto Key: %v", err)
		return 1
	}

	err = os.WriteFile(*out, b, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing encrypted blob %v\n", err)
		return 1
	}
	fmt.Printf("Duplicate Key written to: %s\n", *out)
	return 0
}

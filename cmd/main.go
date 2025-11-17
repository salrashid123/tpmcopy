package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"os"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpmcopy "github.com/salrashid123/tpmcopy"
	duplicatepb "github.com/salrashid123/tpmcopy/duplicatepb"
	"google.golang.org/protobuf/encoding/protojson"
)

const ()

var (
	help = flag.Bool("help", false, "print usage")

	mode = flag.String("mode", "", "publickey | duplicate | import | evict")

	parentKeyType = flag.String("parentKeyType", "rsa_ek", "rsa_ek|ecc_ek|h2 (default rsa_ek)")

	keyType          = flag.String("keyType", "", "type of key to duplicate rsa|ecc|aes|hmac|seal")
	keyName          = flag.String("keyName", "", "User defined description of the key to export")
	tpmPublicKeyFile = flag.String("tpmPublicKeyFile", "/tmp/public.pem", "File to write the public key to (default /tmp/public.pem)")

	rsaScheme  = flag.String("rsaScheme", "rsassa", "rsassa|rsapss (default rsassa)")
	hashScheme = flag.String("hashScheme", "sha256", "sha256|sha384|sha512 (default sha256)")
	eccScheme  = flag.String("eccScheme", "ecc256", "ecc256|ecc384|ecc521 (default ecc256)")
	aesScheme  = flag.String("aesScheme", "cfb", "cbf|cbc|ctr (default cbf)")

	keySize = flag.Uint("keySize", 128, "128 | 256 (default 128)")

	sessionEncryptionName = flag.String("tpm-session-encrypt-with-name", "", "hex encoded TPM object 'name' to use with an encrypted session")
	pcrValues             = flag.String("pcrValues", "", "PCR Bound value (increasing order, comma separated)")
	secret                = flag.String("secret", "", "File with secret to duplicate (rsa | ecc | hex encoded symmetric key or hmac pass)")

	out     = flag.String("out", "/tmp/out.json", "File to write the duplicate to")
	in      = flag.String("in", "/tmp/out.json", "FileName with the key to import")
	pubout  = flag.String("pubout", "/tmp/pub.bin", "(optional) File to write the tpm2_tools compatible public part")
	privout = flag.String("privout", "/tmp/priv.bin", "(optional) File to write the tpm2_tools compatible private part")

	tpmPath  = flag.String("tpm-path", "/dev/tpmrm0", "Create: Path to the TPM device (character device or a Unix socket).")
	password = flag.String("password", "", "Password for the created key")
	ownerpw  = flag.String("ownerpw", "", "Owner Password for the created key")

	persistentHandle       = flag.Uint("persistentHandle", 0x81008001, "persistentHandle to save the key to (default 0x81008001 persistent)")
	parentpersistentHandle = flag.Uint("parentpersistentHandle", 0, "persistentHandle to save the key to (default 0 persistent)")

	version           = flag.Bool("version", false, "print version")
	Commit, Tag, Date string
)

func main() {
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		return 0
	}

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Fprintf(os.Stdout, "Version: %s\n", Tag)
		fmt.Fprintf(os.Stdout, "Date: %s\n", Date)
		fmt.Fprintf(os.Stdout, "Commit: %s\n", Commit)
		return 0
	}

	if *mode == "duplicate" {

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

		if *pcrValues != "" && *password != "" {
			fmt.Fprintf(os.Stderr, "either pcrValues or password must be specified; not both")
			return 1
		}

		pcrMap := make(map[uint][]byte)
		for _, v := range strings.Split(*pcrValues, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					fmt.Fprintf(os.Stderr, " PCR key:value is invalid in parsing %s", v)
					return 1
				}
				hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
				if err != nil {
					fmt.Fprintf(os.Stderr, " PCR key:value is invalid in encoding %s", v)
					return 1
				}
				pcrMap[uint(uv)] = hexEncodedPCR
			}
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
		switch *keyType {
		case "rsa":
			kblock, _ := pem.Decode(f)
			parsedKey, err := x509.ParsePKCS8PrivateKey(kblock.Bytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  error parsing private key : %v", err)
				return 1
			}

			kt = duplicatepb.Secret_RSA
			rsaPriv, ok := parsedKey.(*rsa.PrivateKey)
			if !ok {
				fmt.Fprintf(os.Stderr, "error converting local key to rsa")
				return 1
			}

			var sch tpm2.TPMTRSAScheme
			switch *rsaScheme {
			case "rsassa":
				sch = tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: hsh,
						},
					),
				}
			case "rsapss":
				sch = tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: hsh,
						},
					),
				}
			default:
				fmt.Fprintf(os.Stderr, " unknown rsa scheme selected %s", *rsaScheme)
				return 1
			}

			dupKeyTemplate = tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					SignEncrypt:         true,
					FixedTPM:            false,
					FixedParent:         false,
					SensitiveDataOrigin: false,
					UserWithAuth:        false,
				},

				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						Exponent: uint32(rsaPriv.PublicKey.E),
						Scheme:   sch,
						KeyBits:  tpm2.TPMIRSAKeyBits(rsaPriv.N.BitLen()), // 2048,
					},
				),

				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{
						Buffer: rsaPriv.PublicKey.N.Bytes(),
					},
				),
			}

			sens2B = tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgRSA,
				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPrivateKeyRSA{Buffer: rsaPriv.Primes[0].Bytes()},
				),
			}

			if *password != "" {
				sens2B.AuthValue = tpm2.TPM2BAuth{
					Buffer: []byte(*password), // set any userAuth
				}
			}

		case "ecc":
			kblock, _ := pem.Decode(f)
			parsedKey, err := x509.ParsePKCS8PrivateKey(kblock.Bytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  error parsing private key : %v", err)
				return 1
			}

			kt = duplicatepb.Secret_ECC
			eccPriv, ok := parsedKey.(*ecdsa.PrivateKey)
			if !ok {
				fmt.Fprintf(os.Stderr, "error converting local key to ecc")
				return 1
			}
			pk := eccPriv.PublicKey

			var sch tpm2.TPMUPublicParms
			switch *eccScheme {
			case "ecc256":
				sch = tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
						Scheme: tpm2.TPMTECCScheme{
							Scheme: tpm2.TPMAlgECDSA,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgECDSA,
								&tpm2.TPMSSigSchemeECDSA{
									HashAlg: hsh,
								},
							),
						},
					},
				)
			case "ecc384":
				sch = tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP384,
						Scheme: tpm2.TPMTECCScheme{
							Scheme: tpm2.TPMAlgECDSA,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgECDSA,
								&tpm2.TPMSSigSchemeECDSA{
									HashAlg: hsh,
								},
							),
						},
					},
				)
			case "ecc521":
				sch = tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP521,
						Scheme: tpm2.TPMTECCScheme{
							Scheme: tpm2.TPMAlgECDSA,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgECDSA,
								&tpm2.TPMSSigSchemeECDSA{
									HashAlg: hsh,
								},
							),
						},
					},
				)
			default:
				fmt.Fprintf(os.Stderr, " unknown ecc scheme selected %s", *eccScheme)
				return 1
			}

			dupKeyTemplate = tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgECC,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:            false,
					FixedParent:         false,
					SensitiveDataOrigin: false,
					UserWithAuth:        false,
					SignEncrypt:         true,
				},
				AuthPolicy: tpm2.TPM2BDigest{},
				Parameters: sch,
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCPoint{
						X: tpm2.TPM2BECCParameter{
							Buffer: pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))), //pk.X.Bytes(), // pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))),
						},
						Y: tpm2.TPM2BECCParameter{
							Buffer: pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))), //pk.Y.Bytes(), // pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))),
						},
					},
				),
			}

			sens2B = tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgECC,
				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgECC,
					&tpm2.TPM2BECCParameter{Buffer: eccPriv.D.FillBytes(make([]byte, len(eccPriv.D.Bytes())))},
				),
			}

			if *password != "" {
				sens2B.AuthValue = tpm2.TPM2BAuth{
					Buffer: []byte(*password), // set any userAuth
				}
			}

		case "hmac":

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

		case "aes":
			keySensitive, err := hex.DecodeString(string(f))
			if err != nil {
				fmt.Fprintf(os.Stderr, "  error parsing private key : %v", err)
				return 1
			}
			if len(keySensitive) > aes.BlockSize {
				fmt.Fprintf(os.Stderr, "  error ke must be smaller than aes blocksize bytes : %d , got %d ", aes.BlockSize, len(keySensitive))
				return 1
			}
			kt = duplicatepb.Secret_AES
			sv := make([]byte, 32)
			io.ReadFull(rand.Reader, sv)
			privHash := crypto.SHA256.New()
			privHash.Write(sv)
			privHash.Write(keySensitive)

			var sch tpm2.TPMAlgID
			switch *aesScheme {
			case "cfb":
				sch = tpm2.TPMAlgCFB
			case "ctr":
				sch = tpm2.TPMAlgCTR
			case "cbc":
				sch = tpm2.TPMAlgCBC
			default:
				fmt.Fprintf(os.Stderr, " unknown aes scheme selected %s", *aesScheme)
				return 1
			}

			dupKeyTemplate = tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgSymCipher,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:            false,
					FixedParent:         false,
					SensitiveDataOrigin: false,
					UserWithAuth:        false,
					SignEncrypt:         true,
					Decrypt:             true,
				},
				AuthPolicy: tpm2.TPM2BDigest{},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPMSSymCipherParms{
						Sym: tpm2.TPMTSymDefObject{
							Algorithm: tpm2.TPMAlgAES,
							Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, sch),
							KeyBits: tpm2.NewTPMUSymKeyBits(
								tpm2.TPMAlgAES,
								tpm2.TPMKeyBits(*keySize),
							),
						},
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPM2BDigest{
						Buffer: privHash.Sum(nil),
					},
				),
			}

			sens2B = tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgSymCipher,

				SeedValue: tpm2.TPM2BDigest{
					Buffer: sv,
				},
				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPM2BSymKey{Buffer: keySensitive},
				),
			}

			if *password != "" {
				sens2B.AuthValue = tpm2.TPM2BAuth{
					Buffer: []byte(*password), // set any userAuth
				}
			}

		default:
			fmt.Fprintf(os.Stderr, " unknown --keyType please specify rsa|ecc|aes|hmac\n")
			return 1
		}

		wrappb, err := tpmcopy.Duplicate(ekPububFromPEMTemplate, kt, pkt, *keyName, dupKeyTemplate, sens2B, pcrMap)
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

	if *mode != "import" && *mode != "publickey" && *mode != "evict" {
		fmt.Fprintf(os.Stderr, "--mode must be either import, publickey, evict or duplicate, got  %s", *mode)
		return 1
	}
	rwc, err := tpmcopy.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't open TPM : %v", err)
		return 1
	}
	defer func() {
		rwc.Close()
	}()
	rwr := transport.FromReadWriter(rwc)

	// // get the endorsement key for the local TPM which we will use for parameter encryption
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

	if *sessionEncryptionName != "" {
		if *sessionEncryptionName != hex.EncodeToString(sessionEncryptionRsp.Name.Buffer) {
			fmt.Fprintf(os.Stderr, " session encryption names do not match expected [%s] got [%s]", *sessionEncryptionName, hex.EncodeToString(sessionEncryptionRsp.Name.Buffer))
			return 1
		}
	}

	switch *mode {
	case "publickey":

		if *tpmPublicKeyFile == "" {
			fmt.Fprintf(os.Stderr, "tpmPublicKeyFile must be specified")
			return 1
		}

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
			fmt.Fprintf(os.Stderr, "unsupported --keyType must be either rsa or ecc, got %v\n", *keyType)
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
			TPMDevice:               rwc,
			Ownerpw:                 []byte(*ownerpw),
			SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle,
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
		fmt.Printf("Public Key written to: %s\n", *tpmPublicKeyFile)
		return 0
	case "import":

		if *in == "" || *out == "" {
			fmt.Fprintf(os.Stderr, "in and out  parameters must be specified")
			return 1
		}

		bt, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing reading blob %v\n", err)
			return 1
		}

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
	case "evict":
		if (*persistentHandle) == 0 {
			fmt.Fprintf(os.Stderr, "Error: persistentHandle= cannot be null if mode=evict\n")
			return 1
		}

		/*
			tpm2 startauthsession --session session.ctx --policy-session
			tpm2 policysecret --session session.ctx --object-context endorsement
			tpm2_load -C ek.ctx -c key.ctx -u pub.dat -r priv.dat --auth session:session.ctx
			tpm2_evictcontrol -c key.ctx 0x81008001
		*/

		c, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading keyfile %v", err)
			return 1
		}
		key, err := keyfile.Decode(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error decoding keyfile %v", err)
			return 1
		}

		var rsaKey *tpm2.LoadResponse

		if keyfile.IsMSO(tpm2.TPMHandle(key.Parent), keyfile.TPM_HT_PERMANENT) {
			// the specs https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent
			// state that if the parent is a permanent handle, then we need to run through the H2 Template procedure, otherwise, its
			// persistent handle
			h2primary, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.AuthHandle{
					Handle: key.Parent,
					Name:   tpm2.HandleName(key.Parent),
					Auth:   tpm2.PasswordAuth([]byte(*ownerpw)),
				},
				InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
			}.Execute(rwr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed loading key with parent: %v", err)
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
				fmt.Fprintf(os.Stderr, "error loading key %v", err)
				return 1
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: rsaKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

		} else {
			var t tpm2.TPMTPublic

			switch *parentKeyType {
			case tpmcopy.RSA_EK:
				t = tpm2.RSAEKTemplate
			case tpmcopy.ECC_EK:
				t = tpm2.ECCEKTemplate
			default:
				fmt.Fprintf(os.Stderr, "  unsupported parent key type %s", *parentKeyType)
				return 1
			}

			cCreateEK, err := tpm2.CreatePrimary{

				PrimaryHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth([]byte(*ownerpw)),
				},

				InPublic: tpm2.New2B(t),
			}.Execute(rwr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "can't create primaryObject: %v", err)
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

			load_session, load_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				fmt.Fprintf(os.Stderr, "setting up trial session: %v", err)
				return 1
			}
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth([]byte(*ownerpw)),
				},
				PolicySession: load_session.Handle(),
				NonceTPM:      load_session.NonceTPM(),
			}.Execute(rwr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error setting policy PolicyDuplicationSelect %v", err)
				return 1
			}

			rsaKey, err = tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: cCreateEK.ObjectHandle,
					Name:   tpm2.TPM2BName(cCreateEK.Name),
					Auth:   load_session,
				},
				InPublic:  key.Pubkey,
				InPrivate: key.Privkey,
			}.Execute(rwr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error loading key %v", err)
				return 1
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: rsaKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()
		}

		_, err = tpm2.EvictControl{
			Auth: tpm2.TPMRHOwner,
			ObjectHandle: &tpm2.NamedHandle{
				Handle: rsaKey.ObjectHandle,
				Name:   rsaKey.Name,
			},
			PersistentHandle: tpm2.TPMHandle(*persistentHandle),
		}.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating persistentHandle %v\n", err)
			return 1
		}

	default:
		fmt.Println("Unknown mode: must be publickey|duplicate|import|evict")
		return 1
	}
	return 0
}

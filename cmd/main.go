package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
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

const (
	// pg 14: https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf
	defaultPersistentHandle = 0x81008000
)

var (
	help = flag.Bool("help", false, "print usage")

	mode = flag.String("mode", "", "publickey | duplicate | import | evict")

	keyType               = flag.String("keyType", "type of key to duplicate", "rsa|ecc|aes|hmac")
	keyName               = flag.String("keyName", "", "User defined description of the key to export")
	tpmPublicKeyFile      = flag.String("tpmPublicKeyFile", "/tmp/public.pem", "File to write the public key to (default /tmp/public.pem)")
	parentkeyType         = flag.String("parentKeyType", "rsa", "type of of the parent key (rsa or ecc)")
	sessionEncryptionName = flag.String("tpm-session-encrypt-with-name", "", "hex encoded TPM object 'name' to use with an encrypted session")
	pcrValues             = flag.String("pcrValues", "", "PCR Bound value (increasing order, comma separated)")
	secret                = flag.String("secret", "", "File with secret to duplicate (rsa | ecc | hex encoded symmetric key or hmac pass)")

	parent            = flag.Uint("parent", 0, "parent persistentHandle to create and encode the TPM PEM key file against (default 0x81018000 permanent)")
	useExistingParent = flag.Bool("useExistingParent", false, "Use an existing persistentHandle Parent (default: false)")

	out     = flag.String("out", "/tmp/out.json", "File to write the duplicate to")
	in      = flag.String("in", "/tmp/out.json", "FileName with the key to import")
	pubout  = flag.String("pubout", "/tmp/pub.bin", "(optional) File to write the tpm2_tools compatible public part")
	privout = flag.String("privout", "/tmp/priv.bin", "(optional) File to write the tpm2_tools compatible private part")

	tpmPath  = flag.String("tpm-path", "/dev/tpmrm0", "Create: Path to the TPM device (character device or a Unix socket).")
	password = flag.String("password", "", "Password for the created key")
	ownerpw  = flag.String("ownerpw", "", "Owner Password for the created key")

	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "persistentHandle to save the key to (default 0x81008001 permanent)")

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

	rwc, err := tpmcopy.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stdout, "can't open TPM : %v", err)
		return 1
	}
	defer func() {
		rwc.Close()
	}()
	rwr := transport.FromReadWriter(rwc)

	// // get the endorsement key for the local TPM which we will use for parameter encryption
	sessionEncryptionRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		fmt.Fprintf(os.Stdout, "error creating EK Primary  %v", err)
		return 1
	}
	defer func() {
		_, _ = tpm2.FlushContext{
			FlushHandle: sessionEncryptionRsp.ObjectHandle,
		}.Execute(rwr)
	}()

	if *sessionEncryptionName != "" {
		if *sessionEncryptionName != hex.EncodeToString(sessionEncryptionRsp.Name.Buffer) {
			fmt.Fprintf(os.Stdout, " session encryption names do not match expected [%s] got [%s]", *sessionEncryptionName, hex.EncodeToString(sessionEncryptionRsp.Name.Buffer))
			return 1
		}
	}

	switch *mode {
	case "publickey":

		if *tpmPublicKeyFile == "" {
			fmt.Fprintf(os.Stdout, "tpmPublicKeyFile must be specified")
			return 1
		}

		var t tpm2.TPMTPublic
		switch *parentkeyType {
		case "rsa":
			t = tpm2.RSAEKTemplate
		case "ecc":
			t = tpm2.ECCEKTemplate
		default:
			fmt.Fprintf(os.Stdout, "unsupported --keyType must be either rsa or ecc, got %v\n", *keyType)
			return 1
		}

		cCreateEK, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      tpm2.New2B(t),
		}.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stdout, "can't create object TPM: %v", err)
			return 1
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: cCreateEK.ObjectHandle,
			}
			_, err := flushContextCmd.Execute(rwr)
			if err != nil {
				fmt.Fprintf(os.Stdout, "can't close TPM %v", err)
			}
		}()

		b, err := tpmcopy.GetPublicKey(&tpmcopy.TPMConfig{
			TPMDevice:               rwc,
			Ownerpw:                 []byte(*ownerpw),
			SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle,
		}, cCreateEK.ObjectHandle)
		if err != nil {
			fmt.Fprintf(os.Stdout, "can't getting public key %v", err)
			return 1
		}

		err = os.WriteFile(*tpmPublicKeyFile, b, 0644)
		if err != nil {
			fmt.Fprintf(os.Stdout, "Error writing public key to file %v\n", err)
			return 1
		}
		fmt.Printf("Public Key written to: %s\n", *tpmPublicKeyFile)
		return 0
	case "duplicate":

		if *tpmPublicKeyFile == "" || *secret == "" || *out == "" {
			fmt.Fprintf(os.Stdout, "tpmPublicKeyFile, secret and out  parameters must be specified")
			return 1
		}

		ep, err := os.ReadFile(*tpmPublicKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stdout, " error reading tpmPublicKeyFile : %v", err)
			return 1
		}

		var ekPububFromPEMTemplate tpm2.TPMTPublic
		block, _ := pem.Decode(ep)
		parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stdout, "  error parsing encrypting public key : %v", err)
			return 1
		}

		var pkt duplicatepb.Secret_ParentKeyType

		switch pub := parsedKey.(type) {
		case *rsa.PublicKey:
			rsaPub, ok := parsedKey.(*rsa.PublicKey)
			if !ok {
				fmt.Fprintf(os.Stdout, "  error converting encryptingPublicKey to rsa")
				return 1
			}
			ekPububFromPEMTemplate = tpm2.RSAEKTemplate
			ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{
					Buffer: rsaPub.N.Bytes(),
				},
			)
			pkt = duplicatepb.Secret_EKRSA
		case *ecdsa.PublicKey:
			ecPub, ok := parsedKey.(*ecdsa.PublicKey)
			if !ok {
				fmt.Fprintf(os.Stdout, "  error converting encryptingPublicKey to ecdsa")
				return 1
			}
			ekPububFromPEMTemplate = tpm2.ECCEKTemplate
			ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{
						Buffer: ecPub.X.Bytes(), // ecPub.X.FillBytes(make([]byte, len(ecPub.X.Bytes()))),
					},
					Y: tpm2.TPM2BECCParameter{
						Buffer: ecPub.Y.Bytes(), // ecPub.Y.FillBytes(make([]byte, len(ecPub.Y.Bytes()))),
					},
				},
			)
			pkt = duplicatepb.Secret_EKECC
		default:
			fmt.Fprintf(os.Stdout, "unsupported public key type %v", pub)
			return 1
		}

		// now read in the secret
		f, err := os.ReadFile(*secret)
		if err != nil {
			fmt.Fprintf(os.Stdout, " error reading secret : %v", err)
			return 1
		}

		if *pcrValues != "" && *password != "" {
			fmt.Fprintf(os.Stdout, "either pcrValues or password must be specified; not both")
			return 1
		}

		pcrMap := make(map[uint][]byte)
		for _, v := range strings.Split(*pcrValues, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					fmt.Fprintf(os.Stdout, " PCR key:value is invalid in parsing %s", v)
					return 1
				}
				hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
				if err != nil {
					fmt.Fprintf(os.Stdout, " PCR key:value is invalid in encoding %s", v)
					return 1
				}
				pcrMap[uint(uv)] = hexEncodedPCR
			}
		}

		var dupKeyTemplate tpm2.TPMTPublic
		var sens2B tpm2.TPMTSensitive
		var kt duplicatepb.Secret_KeyType
		switch *keyType {
		case "rsa":
			kblock, _ := pem.Decode(f)
			parsedKey, err := x509.ParsePKCS8PrivateKey(kblock.Bytes)
			if err != nil {
				fmt.Fprintf(os.Stdout, "  error parsing private key : %v", err)
				return 1
			}

			kt = duplicatepb.Secret_RSA
			rsaPriv, ok := parsedKey.(*rsa.PrivateKey)
			if !ok {
				fmt.Fprintf(os.Stdout, "error converting local key to rsa")
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
						Scheme: tpm2.TPMTRSAScheme{
							Scheme: tpm2.TPMAlgRSASSA,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgRSASSA,
								&tpm2.TPMSSigSchemeRSASSA{
									HashAlg: tpm2.TPMAlgSHA256,
								},
							),
						},
						KeyBits: 2048,
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
				fmt.Fprintf(os.Stdout, "  error parsing private key : %v", err)
			}

			kt = duplicatepb.Secret_ECC
			eccPriv, ok := parsedKey.(*ecdsa.PrivateKey)
			if !ok {
				fmt.Fprintf(os.Stdout, "error converting local key to ecc")
			}
			pk := eccPriv.PublicKey

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
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
						Scheme: tpm2.TPMTECCScheme{
							Scheme: tpm2.TPMAlgECDSA,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgECDSA,
								&tpm2.TPMSSigSchemeECDSA{
									HashAlg: tpm2.TPMAlgSHA256,
								},
							),
						},
					},
				),
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
									HashAlg: tpm2.TPMAlgSHA256,
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
				fmt.Fprintf(os.Stdout, "  error parsing private key : %v", err)
			}
			kt = duplicatepb.Secret_AES
			sv := make([]byte, 32)
			io.ReadFull(rand.Reader, sv)
			privHash := crypto.SHA256.New()
			privHash.Write(sv)
			privHash.Write(keySensitive)

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
							Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
							KeyBits: tpm2.NewTPMUSymKeyBits(
								tpm2.TPMAlgAES,
								tpm2.TPMKeyBits(128),
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
			fmt.Fprintf(os.Stdout, " unknown --keyType please specify rsa|ecc|aes|hmac\n")
			return 1
		}

		kParent := tpm2.TPMRHOwner
		if *parent == 0 {
			kParent = tpm2.TPMHandle(*parent)
		}

		wrappb, err := tpmcopy.Duplicate(&tpmcopy.TPMConfig{
			TPMDevice:               rwc,
			SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle,
			Ownerpw:                 []byte(*ownerpw),
		}, ekPububFromPEMTemplate, kt, pkt, kParent, *keyName, dupKeyTemplate, sens2B, pcrMap)
		if err != nil {
			fmt.Fprintf(os.Stdout, "error duplicating %v", err)
			return 1
		}

		b, err := protojson.Marshal(&wrappb)
		if err != nil {
			fmt.Fprintf(os.Stdout, "failed to wrap proto Key: %v", err)
			return 1
		}

		err = os.WriteFile(*out, b, 0666)
		if err != nil {
			fmt.Fprintf(os.Stdout, "Error writing encrypted blob %v\n", err)
			return 1
		}
		fmt.Printf("Duplicate Key written to: %s\n", *out)
	case "import":

		if *in == "" || *out == "" {
			fmt.Fprintf(os.Stdout, "in and out  parameters must be specified")
			return 1
		}

		var parentHandle tpm2.TPMHandle
		if *useExistingParent {
			if *parent == 0 {
				fmt.Fprintf(os.Stdout, "--parent= cannot be 0 if useExistingParent is set")
				return 1
			}
			parentHandle = tpm2.TPMHandle(uint32(*parent))
		} else {
			var t tpm2.TPMTPublic
			switch *parentkeyType {
			case "rsa":
				t = tpm2.RSAEKTemplate
			case "ecc":
				t = tpm2.ECCEKTemplate
			default:
				fmt.Fprintf(os.Stdout, "unsupported KeyType %v\n", *keyType)
				return 1
			}

			cCreateEK, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(t),
			}.Execute(rwr)
			if err != nil {
				fmt.Fprintf(os.Stdout, "can't create object TPM: %v", err)
				return 1
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: cCreateEK.ObjectHandle,
				}
				_, err := flushContextCmd.Execute(rwr)
				if err != nil {
					fmt.Fprintf(os.Stdout, "can't closing ek %v", err)
				}
			}()

			if *parent == 0 {
				*parent = defaultPersistentHandle
			}
			kp, err := tpm2.ReadPublic{
				ObjectHandle: tpm2.TPMHandle(uint32(*parent)),
			}.Execute(rwr)
			if err == nil {
				_, err = tpm2.EvictControl{
					Auth: tpm2.TPMRHOwner,
					ObjectHandle: &tpm2.NamedHandle{
						Handle: tpm2.TPMIDHPersistent(uint32(*parent)),
						Name:   kp.Name,
					},
					PersistentHandle: tpm2.TPMHandle(uint32(*parent)),
				}.Execute(rwr)
				if err != nil {
					fmt.Fprintf(os.Stdout, "error exsting persistentHandle [%s] already defined: ", strconv.FormatUint(uint64(*parent), 16))
					return 1
				}
			}

			_, err = tpm2.EvictControl{
				Auth: tpm2.TPMRHOwner,
				ObjectHandle: &tpm2.NamedHandle{
					Handle: cCreateEK.ObjectHandle,
					Name:   cCreateEK.Name,
				},
				PersistentHandle: tpm2.TPMHandle(uint32(*parent)),
			}.Execute(rwr)
			if err != nil {
				fmt.Fprintf(os.Stdout, "Error creating persistentHandle %v\n", err)
				return 1
			}
			parentHandle = tpm2.TPMHandle(*parent)
		}

		bt, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintf(os.Stdout, "Error writing reading blob %v\n", err)
			return 1
		}

		var k duplicatepb.Secret

		err = protojson.Unmarshal(bt, &k)
		if err != nil {
			fmt.Fprintf(os.Stdout, "failed to unmarshall proto Key: %v", err)
			return 1
		}

		tpmKey, err := tpmcopy.Import(&tpmcopy.TPMConfig{
			TPMDevice:               rwc,
			Ownerpw:                 []byte(*ownerpw),
			SessionEncryptionHandle: sessionEncryptionRsp.ObjectHandle}, parentHandle, k)
		if err != nil {
			fmt.Fprintf(os.Stdout, "failed to import Key: %v", err)
			return 1
		}
		kfb := new(bytes.Buffer)
		err = keyfile.Encode(kfb, &tpmKey)
		if err != nil {
			fmt.Fprintf(os.Stdout, "Error writing public key to file %v\n", err)
			return 1
		}
		err = os.WriteFile(*out, kfb.Bytes(), 0644)
		if err != nil {
			fmt.Fprintf(os.Stdout, "Error writing public key to file %v\n", err)
			return 1
		}

		if *pubout != "" {
			f := tpm2.Marshal(tpmKey.Pubkey)
			err = os.WriteFile(*pubout, f, 0644)
			if err != nil {
				fmt.Fprintf(os.Stdout, "Error writing public key to file %v\n", err)
				return 1
			}
		}
		if *privout != "" {
			f := tpm2.Marshal(tpmKey.Privkey)
			err = os.WriteFile(*privout, f, 0644)
			if err != nil {
				fmt.Fprintf(os.Stdout, "Error writing public key to file %v\n", err)
				return 1
			}
		}

		fmt.Printf("Imported Key written to: %s\n", *out)
	case "evict":
		if (*persistentHandle) == 0 {
			fmt.Fprintf(os.Stdout, "Error: persistentHandle= cannot be null if mode=evict\n")
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
			fmt.Fprintf(os.Stdout, "error reading keyfile %v", err)
			return 1
		}
		key, err := keyfile.Decode(c)
		if err != nil {
			fmt.Fprintf(os.Stdout, "error decoding keyfile %v", err)
			return 1
		}

		var t tpm2.TPMTPublic
		switch *parentkeyType {
		case "rsa":
			t = tpm2.RSAEKTemplate
		case "ecc":
			t = tpm2.ECCEKTemplate
		default:
			fmt.Fprintf(os.Stdout, "unsupported KeyType %v\n", *keyType)
			return 1
		}
		cCreateEK, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      tpm2.New2B(t),
		}.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stdout, "can't create primaryObject: %v", err)
			return 1
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: cCreateEK.ObjectHandle,
			}
			_, err := flushContextCmd.Execute(rwr)
			if err != nil {
				fmt.Fprintf(os.Stdout, "can't closing ek %v", err)
			}
		}()

		load_session, load_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			fmt.Fprintf(os.Stdout, "setting up trial session: %v", err)
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
			fmt.Fprintf(os.Stdout, "error setting policy PolicyDuplicationSelect %v", err)
			return 1
		}

		rsaKey, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: cCreateEK.ObjectHandle,
				Name:   tpm2.TPM2BName(cCreateEK.Name),
				Auth:   load_session,
			},
			InPublic:  key.Pubkey,
			InPrivate: key.Privkey,
		}.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stdout, "error loading key %v", err)
			return 1
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: rsaKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		_, err = tpm2.EvictControl{
			Auth: tpm2.TPMRHOwner,
			ObjectHandle: &tpm2.NamedHandle{
				Handle: rsaKey.ObjectHandle,
				Name:   rsaKey.Name,
			},
			PersistentHandle: tpm2.TPMHandle(*persistentHandle),
		}.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stdout, "Error creating persistentHandle %v\n", err)
			return 1
		}

	default:
		fmt.Println("Unknown mode: must be publickey|duplicate|import|evict")
		return 1
	}
	return 0
}

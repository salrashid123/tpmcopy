package tpmcopy

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	stdhmac "crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	duplicatepb "github.com/salrashid123/tpmcopy/duplicatepb"
	"github.com/stretchr/testify/require"
)

const (
	maxInputBuffer  = 1024
	maxDigestBuffer = 1024
)

var ()

const (
	swTPMPath = "127.0.0.1:2321"
)

func getPublicKey(t *testing.T, tpmpublic tpm2.TPMTPublic, rwr transport.TPM) ([]byte, tpm2.TPMHandle, tpm2.TPMTPublic, error) {

	createEKB, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpmpublic),
	}.Execute(rwr)
	if err != nil {
		return nil, 0, tpm2.TPMTPublic{}, err
	}

	pubEKB, err := tpm2.ReadPublic{
		ObjectHandle: createEKB.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		return nil, 0, tpm2.TPMTPublic{}, err
	}

	outPubB, err := pubEKB.OutPublic.Contents()
	if err != nil {
		return nil, 0, tpm2.TPMTPublic{}, err
	}

	var pub any
	switch tpmpublic.Type {
	case tpm2.TPMAlgRSA:
		rsaDetailB, err := outPubB.Parameters.RSADetail()
		if err != nil {
			return nil, 0, tpm2.TPMTPublic{}, err
		}

		rsaUniqueB, err := outPubB.Unique.RSA()
		if err != nil {
			return nil, 0, tpm2.TPMTPublic{}, err
		}

		pub, err = tpm2.RSAPub(rsaDetailB, rsaUniqueB)
		if err != nil {
			return nil, 0, tpm2.TPMTPublic{}, err
		}
	case tpm2.TPMAlgECC:
		ecDetail, err := outPubB.Parameters.ECCDetail()
		if err != nil {
			return nil, 0, tpm2.TPMTPublic{}, err
		}

		crv, err := ecDetail.CurveID.Curve()
		require.NoError(t, err)
		if err != nil {
			return nil, 0, tpm2.TPMTPublic{}, err
		}

		eccUnique, err := outPubB.Unique.ECC()
		if err != nil {
			return nil, 0, tpm2.TPMTPublic{}, err
		}

		pub = &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
	default:
		return nil, 0, tpm2.TPMTPublic{}, fmt.Errorf("Unsupported public key %v", tpmpublic.Type)
	}

	rB, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, 0, tpm2.TPMTPublic{}, err
	}
	pemdataB := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rB,
		},
	)

	var ekPububFromPEMTemplate tpm2.TPMTPublic
	eblock, _ := pem.Decode(pemdataB)
	parsedKey, err := x509.ParsePKIXPublicKey(eblock.Bytes)
	require.NoError(t, err)

	switch pub := parsedKey.(type) {
	case *rsa.PublicKey:
		rsaPub, ok := parsedKey.(*rsa.PublicKey)
		require.True(t, ok)
		ekPububFromPEMTemplate = tpm2.RSAEKTemplate
		ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: rsaPub.N.Bytes(),
			},
		)
	case *ecdsa.PublicKey:
		ecPub, ok := parsedKey.(*ecdsa.PublicKey)
		require.True(t, ok)
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
	default:

		return nil, 0, tpm2.TPMTPublic{}, fmt.Errorf("unknown key type %v", pub)

	}

	return pemdataB, createEKB.ObjectHandle, ekPububFromPEMTemplate, nil
}

func TestGetPublicRSAEK(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	createEKB, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKB.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	pubEKB, err := tpm2.ReadPublic{
		ObjectHandle: createEKB.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	outPubB, err := pubEKB.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetailB, err := outPubB.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUniqueB, err := outPubB.Unique.RSA()
	require.NoError(t, err)

	rsaPubB, err := tpm2.RSAPub(rsaDetailB, rsaUniqueB)
	require.NoError(t, err)

	rB, err := x509.MarshalPKIXPublicKey(rsaPubB)
	require.NoError(t, err)
	pemdataB := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rB,
		},
	)

	tempDirB := t.TempDir()
	filePathB := filepath.Join(tempDirB, "ekpub.pem")
	err = os.WriteFile(filePathB, pemdataB, 0644)
	require.NoError(t, err)

	k, err := GetPublicKey(&TPMConfig{
		TPMDevice: tpmDeviceB,
	}, createEKB.ObjectHandle)
	require.NoError(t, err)

	require.Equal(t, pemdataB, k)
}

func TestGetPublicECCEK(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	createEKB, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKB.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	pubEKB, err := tpm2.ReadPublic{
		ObjectHandle: createEKB.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	outPubB, err := pubEKB.OutPublic.Contents()
	require.NoError(t, err)

	eccDetailB, err := outPubB.Parameters.ECCDetail()
	require.NoError(t, err)

	crv, err := eccDetailB.CurveID.Curve()
	require.NoError(t, err)

	eccUnique, err := outPubB.Unique.ECC()
	require.NoError(t, err)

	epub := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	rB, err := x509.MarshalPKIXPublicKey(epub)
	require.NoError(t, err)
	pemdataB := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rB,
		},
	)

	tempDirB := t.TempDir()
	filePathB := filepath.Join(tempDirB, "ekpub.pem")
	err = os.WriteFile(filePathB, pemdataB, 0644)
	require.NoError(t, err)

	k, err := GetPublicKey(&TPMConfig{
		TPMDevice: tpmDeviceB,
	}, createEKB.ObjectHandle)
	require.NoError(t, err)

	require.Equal(t, pemdataB, k)
}

func TestDuplicatePasswordRSA(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)
	defer tpmDeviceB.Close()

	// $ swtpm_setup --print-capabilities | jq '.'
	// {
	//   "type": "swtpm_setup",
	//   "features": [
	//     "tpm-1.2",
	//     "tpm-2.0",
	//     "cmdarg-keyfile-fd",
	//     "cmdarg-pwdfile-fd",
	//     "tpm12-not-need-root",
	//     "cmdarg-write-ek-cert-files",
	//     "cmdarg-create-config-files",
	//     "cmdarg-reconfigure-pcr-banks",
	//     "tpm2-rsa-keysize-2048",
	//     "tpm2-rsa-keysize-3072"
	//   ],
	//   "version": "0.7.1"
	// }

	tests := []struct {
		name     string
		password string

		hsh     tpm2.TPMAlgID
		alg     string
		keyFile string
	}{
		{"SHA256RSASSA", "bar", tpm2.TPMAlgSHA256, "rsassa", "testdata/certs/key_rsa_2048.pem"},

		{"SHA256RSASSA_3072", "bar", tpm2.TPMAlgSHA256, "rsassa", "testdata/certs/key_rsa_3072.pem"},
		{"SHA384RSASSA", "bar", tpm2.TPMAlgSHA384, "rsassa", "testdata/certs/key_rsa_2048.pem"},
		{"SHA512RSASSA", "bar", tpm2.TPMAlgSHA512, "rsassa", "testdata/certs/key_rsa_2048.pem"},

		{"SHA256RSAPSS", "bar", tpm2.TPMAlgSHA256, "rsapss", "testdata/certs/key_rsa_2048.pem"},
		{"SHA384RSAPSS", "bar", tpm2.TPMAlgSHA384, "rsapss", "testdata/certs/key_rsa_2048.pem"},
		{"SHA512RSAPSS", "bar", tpm2.TPMAlgSHA512, "rsapss", "testdata/certs/key_rsa_2048.pem"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// ***** first get the ekpubB

			_, ekHandle, ekPububFromPEMTemplate, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: ekHandle,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			/// now read the RSA private key to import/export

			kbytes, err := os.ReadFile(tc.keyFile)
			require.NoError(t, err)

			block, _ := pem.Decode(kbytes)
			require.NoError(t, err)

			// Parse the PKCS#1 private key
			privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)

			rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
			require.True(t, ok)

			var sch tpm2.TPMTRSAScheme
			switch tc.alg {
			case "rsassa":
				sch = tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tc.hsh,
						},
					),
				}
			case "rsapss":
				sch = tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: tc.hsh,
						},
					),
				}
			}

			dupKeyTemplate := tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					SignEncrypt:         true,
					FixedTPM:            false,
					FixedParent:         false,
					SensitiveDataOrigin: false,
					UserWithAuth:        true,
				},

				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						Exponent: uint32(rsaPrivateKey.PublicKey.E),
						Scheme:   sch,
						KeyBits:  tpm2.TPMIRSAKeyBits(rsaPrivateKey.N.BitLen()), //2048,
					},
				),

				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{
						Buffer: rsaPrivateKey.PublicKey.N.Bytes(),
					},
				),
			}

			sens2B := tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgRSA,
				AuthValue: tpm2.TPM2BAuth{
					Buffer: []byte(tc.password), // set any userAuth
				},
				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPrivateKeyRSA{Buffer: rsaPrivateKey.Primes[0].Bytes()},
				),
			}

			s, err := Duplicate(ekPububFromPEMTemplate, duplicatepb.Secret_RSA, duplicatepb.Secret_EndorsementRSA, "", dupKeyTemplate, sens2B, nil, false)
			require.NoError(t, err)

			/// now import

			sessionEncryptionRspB, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwrB)
			require.NoError(t, err)
			defer func() {
				_, _ = tpm2.FlushContext{
					FlushHandle: sessionEncryptionRspB.ObjectHandle,
				}.Execute(rwrB)
			}()

			key, err := Import(&TPMConfig{
				TPMDevice:               tpmDeviceB,
				SessionEncryptionHandle: sessionEncryptionRspB.ObjectHandle,
			}, ekHandle, s)
			require.NoError(t, err)

			_, _ = tpm2.FlushContext{
				FlushHandle: sessionEncryptionRspB.ObjectHandle,
			}.Execute(rwrB)
			require.NoError(t, err)

			// now load the key

			_, ekHandleB, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: ekHandleB,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			pubEKB, err := tpm2.ReadPublic{
				ObjectHandle: ekHandleB,
			}.Execute(rwrB)
			require.NoError(t, err)

			load_session, load_session_cleanup, err := tpm2.PolicySession(rwrB, tpm2.TPMAlgSHA256, 16)
			require.NoError(t, err)
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth(nil),
				},
				PolicySession: load_session.Handle(),
				NonceTPM:      load_session.NonceTPM(),
			}.Execute(rwrB)
			require.NoError(t, err)

			regenRSAKey, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: ekHandleB,
					Name:   pubEKB.Name,
					Auth:   load_session,
				},
				InPublic:  key.Pubkey,
				InPrivate: key.Privkey,
			}.Execute(rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: regenRSAKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			pubregen, err := tpm2.ReadPublic{
				ObjectHandle: regenRSAKey.ObjectHandle,
			}.Execute(rwrB)
			require.NoError(t, err)

			outPubBregen, err := pubregen.OutPublic.Contents()
			require.NoError(t, err)

			rsaDetailBregen, err := outPubBregen.Parameters.RSADetail()
			require.NoError(t, err)

			rsaUniqueBregen, err := outPubBregen.Unique.RSA()
			require.NoError(t, err)

			rsaPubBregen, err := tpm2.RSAPub(rsaDetailBregen, rsaUniqueBregen)
			require.NoError(t, err)

			require.Equal(t, rsaPubBregen, &rsaPrivateKey.PublicKey)

			stringToSign := "foo"

			b := []byte(stringToSign)

			hh, err := tc.hsh.Hash()
			require.NoError(t, err)

			h := hh.New()
			h.Write(b)
			digest := h.Sum(nil)

			svc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(tc.password), pubEKB.Name, ekHandle)
			require.NoError(t, err)
			or_sess, or_sess_cleanup, err := svc.GetSession()
			require.NoError(t, err)
			defer or_sess_cleanup()

			var sigsch tpm2.TPMTSigScheme
			switch tc.alg {
			case "rsassa":
				sigsch = tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSchemeHash{
							HashAlg: tc.hsh,
						},
					),
				}
			case "rsapss":
				sigsch = tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSchemeHash{
							HashAlg: tc.hsh,
						},
					),
				}
			}

			sign := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: regenRSAKey.ObjectHandle,
					Name:   regenRSAKey.Name,
					Auth:   or_sess, //tpm2.PasswordAuth([]byte(tc.password)),
				},
				Digest: tpm2.TPM2BDigest{
					Buffer: digest[:],
				},
				InScheme: sigsch,
				Validation: tpm2.TPMTTKHashCheck{
					Tag: tpm2.TPMSTHashCheck,
				},
			}

			_, err = sign.Execute(rwrB)
			require.NoError(t, err)

		})
	}

}

func TestDuplicateNoPolicyRSA(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)
	defer tpmDeviceB.Close()

	tests := []struct {
		name string

		password string
		hsh      tpm2.TPMAlgID
		alg      string
		keyFile  string
	}{
		{"UserAuthTrue", "foo", tpm2.TPMAlgSHA256, "rsassa", "testdata/certs/key_rsa_2048.pem"},
		{"UserAuthTrueNoPassword", "", tpm2.TPMAlgSHA256, "rsassa", "testdata/certs/key_rsa_2048.pem"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// ***** first get the ekpubB

			_, ekHandle, ekPububFromPEMTemplate, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: ekHandle,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			/// now read the RSA private key to import/export

			kbytes, err := os.ReadFile(tc.keyFile)
			require.NoError(t, err)

			block, _ := pem.Decode(kbytes)
			require.NoError(t, err)

			// Parse the PKCS#1 private key
			privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)

			rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
			require.True(t, ok)

			var sch tpm2.TPMTRSAScheme
			switch tc.alg {
			case "rsassa":
				sch = tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tc.hsh,
						},
					),
				}
			case "rsapss":
				sch = tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: tc.hsh,
						},
					),
				}
			}

			dupKeyTemplate := tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					SignEncrypt:         true,
					FixedTPM:            false,
					FixedParent:         false,
					SensitiveDataOrigin: false,
					UserWithAuth:        true,
				},

				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						Exponent: uint32(rsaPrivateKey.PublicKey.E),
						Scheme:   sch,
						KeyBits:  tpm2.TPMIRSAKeyBits(rsaPrivateKey.N.BitLen()), //2048,
					},
				),

				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{
						Buffer: rsaPrivateKey.PublicKey.N.Bytes(),
					},
				),
			}

			sens2B := tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgRSA,
				AuthValue: tpm2.TPM2BAuth{
					Buffer: []byte(tc.password), // set any userAuth
				},
				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPrivateKeyRSA{Buffer: rsaPrivateKey.Primes[0].Bytes()},
				),
			}

			s, err := Duplicate(ekPububFromPEMTemplate, duplicatepb.Secret_RSA, duplicatepb.Secret_EndorsementRSA, "", dupKeyTemplate, sens2B, nil, true)
			require.NoError(t, err)

			/// now import

			sessionEncryptionRspB, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwrB)
			require.NoError(t, err)
			defer func() {
				_, _ = tpm2.FlushContext{
					FlushHandle: sessionEncryptionRspB.ObjectHandle,
				}.Execute(rwrB)
			}()

			key, err := Import(&TPMConfig{
				TPMDevice:               tpmDeviceB,
				SessionEncryptionHandle: sessionEncryptionRspB.ObjectHandle,
			}, ekHandle, s)
			require.NoError(t, err)

			_, _ = tpm2.FlushContext{
				FlushHandle: sessionEncryptionRspB.ObjectHandle,
			}.Execute(rwrB)
			require.NoError(t, err)

			// now load the key

			_, ekHandleB, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: ekHandleB,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			pubEKB, err := tpm2.ReadPublic{
				ObjectHandle: ekHandleB,
			}.Execute(rwrB)
			require.NoError(t, err)

			load_session, load_session_cleanup, err := tpm2.PolicySession(rwrB, tpm2.TPMAlgSHA256, 16)
			require.NoError(t, err)
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth(nil),
				},
				PolicySession: load_session.Handle(),
				NonceTPM:      load_session.NonceTPM(),
			}.Execute(rwrB)
			require.NoError(t, err)

			regenRSAKey, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: ekHandleB,
					Name:   pubEKB.Name,
					Auth:   load_session,
				},
				InPublic:  key.Pubkey,
				InPrivate: key.Privkey,
			}.Execute(rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: regenRSAKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			pubregen, err := tpm2.ReadPublic{
				ObjectHandle: regenRSAKey.ObjectHandle,
			}.Execute(rwrB)
			require.NoError(t, err)

			outPubBregen, err := pubregen.OutPublic.Contents()
			require.NoError(t, err)

			rsaDetailBregen, err := outPubBregen.Parameters.RSADetail()
			require.NoError(t, err)

			rsaUniqueBregen, err := outPubBregen.Unique.RSA()
			require.NoError(t, err)

			rsaPubBregen, err := tpm2.RSAPub(rsaDetailBregen, rsaUniqueBregen)
			require.NoError(t, err)

			require.Equal(t, rsaPubBregen, &rsaPrivateKey.PublicKey)

			stringToSign := "foo"

			b := []byte(stringToSign)

			hh, err := tc.hsh.Hash()
			require.NoError(t, err)

			h := hh.New()
			h.Write(b)
			digest := h.Sum(nil)

			var sigsch tpm2.TPMTSigScheme
			switch tc.alg {
			case "rsassa":
				sigsch = tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSchemeHash{
							HashAlg: tc.hsh,
						},
					),
				}
			case "rsapss":
				sigsch = tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSchemeHash{
							HashAlg: tc.hsh,
						},
					),
				}
			}

			sign := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: regenRSAKey.ObjectHandle,
					Name:   regenRSAKey.Name,
					Auth:   tpm2.PasswordAuth([]byte(tc.password)),
				},
				Digest: tpm2.TPM2BDigest{
					Buffer: digest[:],
				},
				InScheme: sigsch,
				Validation: tpm2.TPMTTKHashCheck{
					Tag: tpm2.TPMSTHashCheck,
				},
			}

			_, err = sign.Execute(rwrB)
			require.NoError(t, err)

		})
	}

}

func TestImportPersistent(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	defer tpmDeviceB.Close()

	// ***** first get the ekpubB

	_, ekHandle, ekPububFromPEMTemplate, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: ekHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	/// now read the RSA private key to import/export

	keyFile := "testdata/certs/key_rsa_2048.pem"
	kbytes, err := os.ReadFile(keyFile)
	require.NoError(t, err)

	block, _ := pem.Decode(kbytes)
	require.NoError(t, err)

	// Parse the PKCS#1 private key
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	require.True(t, ok)

	dupKeyTemplate := tpm2.TPMTPublic{
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
				Exponent: uint32(rsaPrivateKey.PublicKey.E),
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
				Buffer: rsaPrivateKey.PublicKey.N.Bytes(),
			},
		),
	}

	sens2B := tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgRSA,
		AuthValue: tpm2.TPM2BAuth{
			Buffer: []byte(nil), // set any userAuth
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPrivateKeyRSA{Buffer: rsaPrivateKey.Primes[0].Bytes()},
		),
	}

	s, err := Duplicate(ekPububFromPEMTemplate, duplicatepb.Secret_RSA, duplicatepb.Secret_EndorsementRSA, "", dupKeyTemplate, sens2B, nil, false)
	// ************************
	require.NoError(t, err)

	/// now import

	sessionEncryptionRspB, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwrB)
	require.NoError(t, err)
	defer func() {
		_, _ = tpm2.FlushContext{
			FlushHandle: sessionEncryptionRspB.ObjectHandle,
		}.Execute(rwrB)
	}()

	// set a persistentHandle for the parent
	// this is useful for PEM encoded files to load
	pubEKB, err := tpm2.ReadPublic{
		ObjectHandle: ekHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	_, err = tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(defaultParentPersistentHandle),
	}.Execute(rwrB)
	if err == nil {
		_, err = tpm2.EvictControl{
			Auth: tpm2.TPMRHOwner,
			ObjectHandle: &tpm2.NamedHandle{
				Handle: tpm2.TPMIDHPersistent(defaultParentPersistentHandle),
				Name:   tpm2.HandleName(tpm2.TPMIDHPersistent(defaultParentPersistentHandle)),
			},
			PersistentHandle: tpm2.TPMIDHPersistent(defaultParentPersistentHandle),
		}.Execute(rwrB)
		require.NoError(t, err)
	}

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: ekHandle,
			Name:   pubEKB.Name,
		},
		PersistentHandle: tpm2.TPMHandle(defaultParentPersistentHandle),
	}.Execute(rwrB)
	require.NoError(t, err)

	key, err := Import(&TPMConfig{
		TPMDevice:               tpmDeviceB,
		SessionEncryptionHandle: sessionEncryptionRspB.ObjectHandle,
	}, tpm2.TPMHandle(defaultParentPersistentHandle), s)
	require.NoError(t, err)

	_, _ = tpm2.FlushContext{
		FlushHandle: sessionEncryptionRspB.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	// now load the key

	_, ekHandleB, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: ekHandleB,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	load_session, load_session_cleanup, err := tpm2.PolicySession(rwrB, tpm2.TPMAlgSHA256, 16)
	require.NoError(t, err)
	defer load_session_cleanup()

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth(nil),
		},
		PolicySession: load_session.Handle(),
		NonceTPM:      load_session.NonceTPM(),
	}.Execute(rwrB)
	require.NoError(t, err)

	regenRSAKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: ekHandleB,
			Name:   pubEKB.Name,
			Auth:   load_session,
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: regenRSAKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	pubregen, err := tpm2.ReadPublic{
		ObjectHandle: regenRSAKey.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	outPubBregen, err := pubregen.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetailBregen, err := outPubBregen.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUniqueBregen, err := outPubBregen.Unique.RSA()
	require.NoError(t, err)

	rsaPubBregen, err := tpm2.RSAPub(rsaDetailBregen, rsaUniqueBregen)
	require.NoError(t, err)

	require.Equal(t, rsaPubBregen, &rsaPrivateKey.PublicKey)

	stringToSign := "foo"

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	svc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(nil), pubEKB.Name, ekHandle)
	require.NoError(t, err)
	or_sess, or_sess_cleanup, err := svc.GetSession()
	require.NoError(t, err)
	defer or_sess_cleanup()

	sign := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: regenRSAKey.ObjectHandle,
			Name:   regenRSAKey.Name,
			Auth:   or_sess, //tpm2.PasswordAuth([]byte(tc.password)),
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

	_, err = sign.Execute(rwrB)
	require.NoError(t, err)

}

func TestDuplicatePasswordPCR(t *testing.T) {
	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	defer tpmDeviceB.Close()

	tests := []struct {
		name          string
		pcrValues     string
		shouldSucceed bool
	}{
		{"policy", "23:0000000000000000000000000000000000000000000000000000000000000000", true},
		{"policyFail", "23:f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			pcrMap := make(map[uint][]byte)
			for _, v := range strings.Split(tc.pcrValues, ",") {
				entry := strings.Split(v, ":")
				if len(entry) == 2 {
					uv, err := strconv.ParseUint(entry[0], 10, 32)
					require.NoError(t, err)
					hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
					require.NoError(t, err)
					pcrMap[uint(uv)] = hexEncodedPCR
				}
			}

			// ***** first get the ekpubB

			ekpubPEM, ekHandle, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)

			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: ekHandle,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			var ekPububFromPEMTemplate tpm2.TPMTPublic
			eblock, _ := pem.Decode(ekpubPEM)
			parsedKey, err := x509.ParsePKIXPublicKey(eblock.Bytes)
			require.NoError(t, err)

			switch pub := parsedKey.(type) {
			case *rsa.PublicKey:
				rsaPub, ok := parsedKey.(*rsa.PublicKey)
				require.True(t, ok)
				ekPububFromPEMTemplate = tpm2.RSAEKTemplate
				ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{
						Buffer: rsaPub.N.Bytes(),
					},
				)
			case *ecdsa.PublicKey:
				ecPub, ok := parsedKey.(*ecdsa.PublicKey)
				require.True(t, ok)
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
			default:
				require.Fail(t, "unknonw public key type %v", pub)
			}

			/// now read the RSA private key to import/export

			keyFile := "testdata/certs/key_rsa_2048.pem"
			kbytes, err := os.ReadFile(keyFile)
			require.NoError(t, err)

			block, _ := pem.Decode(kbytes)
			require.NoError(t, err)

			// Parse the PKCS#1 private key
			privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)

			rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
			require.True(t, ok)

			dupKeyTemplate := tpm2.TPMTPublic{
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
						Exponent: uint32(rsaPrivateKey.PublicKey.E),
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
						Buffer: rsaPrivateKey.PublicKey.N.Bytes(),
					},
				),
			}

			sens2B := tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgRSA,
				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPrivateKeyRSA{Buffer: rsaPrivateKey.Primes[0].Bytes()},
				),
			}

			s, err := Duplicate(ekPububFromPEMTemplate, duplicatepb.Secret_RSA, duplicatepb.Secret_EndorsementRSA, "", dupKeyTemplate, sens2B, pcrMap, false)

			// ************************

			require.NoError(t, err)

			/// now import

			sessionEncryptionRspB, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwrB)
			require.NoError(t, err)
			defer func() {
				_, _ = tpm2.FlushContext{
					FlushHandle: sessionEncryptionRspB.ObjectHandle,
				}.Execute(rwrB)
			}()

			key, err := Import(&TPMConfig{
				TPMDevice:               tpmDeviceB,
				SessionEncryptionHandle: sessionEncryptionRspB.ObjectHandle,
			}, ekHandle, s)
			require.NoError(t, err)

			_, _ = tpm2.FlushContext{
				FlushHandle: sessionEncryptionRspB.ObjectHandle,
			}.Execute(rwrB)
			require.NoError(t, err)

			// now load the key

			_, ekHandleB, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: ekHandleB,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			pubEKB, err := tpm2.ReadPublic{
				ObjectHandle: ekHandleB,
			}.Execute(rwrB)
			require.NoError(t, err)

			load_session, load_session_cleanup, err := tpm2.PolicySession(rwrB, tpm2.TPMAlgSHA256, 16)
			require.NoError(t, err)
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth(nil),
				},
				PolicySession: load_session.Handle(),
				NonceTPM:      load_session.NonceTPM(),
			}.Execute(rwrB)
			require.NoError(t, err)

			regenRSAKey, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: ekHandleB,
					Name:   pubEKB.Name,
					Auth:   load_session,
				},
				InPublic:  key.Pubkey,
				InPrivate: key.Privkey,
			}.Execute(rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: regenRSAKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			pubregen, err := tpm2.ReadPublic{
				ObjectHandle: regenRSAKey.ObjectHandle,
			}.Execute(rwrB)
			require.NoError(t, err)

			outPubBregen, err := pubregen.OutPublic.Contents()
			require.NoError(t, err)

			rsaDetailBregen, err := outPubBregen.Parameters.RSADetail()
			require.NoError(t, err)

			rsaUniqueBregen, err := outPubBregen.Unique.RSA()
			require.NoError(t, err)

			rsaPubBregen, err := tpm2.RSAPub(rsaDetailBregen, rsaUniqueBregen)
			require.NoError(t, err)

			require.Equal(t, rsaPubBregen, &rsaPrivateKey.PublicKey)

			stringToSign := "foo"

			b := []byte(stringToSign)

			h := sha256.New()
			h.Write(b)
			digest := h.Sum(nil)

			epub, err := tpm2.ReadPublic{
				ObjectHandle: tpm2.TPMIDHObject(ekHandle),
			}.Execute(rwrB)
			require.NoError(t, err)

			_, pcrList, pcrDigest, err := getPCRMap(tpm2.TPMAlgSHA256, pcrMap)
			require.NoError(t, err)

			se, err := NewPCRAndDuplicateSelectSession(rwrB, []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
				},
			}, tpm2.TPM2BDigest{Buffer: pcrDigest}, nil, epub.Name, ekHandle)
			require.NoError(t, err)
			or_sess, or_cleanup, err := se.GetSession()
			if tc.shouldSucceed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			defer or_cleanup()

			sign := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: regenRSAKey.ObjectHandle,
					Name:   regenRSAKey.Name,
					Auth:   or_sess,
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

			_, err = sign.Execute(rwrB)
			if tc.shouldSucceed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}

}

func TestDuplicateECC(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	defer tpmDeviceB.Close()

	// ***** first get the ekpubB

	password := "somepassword"

	ekpubPEM, ekHandle, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: ekHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	var ekPububFromPEMTemplate tpm2.TPMTPublic
	eblock, _ := pem.Decode(ekpubPEM)
	parsedKey, err := x509.ParsePKIXPublicKey(eblock.Bytes)
	require.NoError(t, err)

	switch pub := parsedKey.(type) {
	case *rsa.PublicKey:
		rsaPub, ok := parsedKey.(*rsa.PublicKey)
		require.True(t, ok)
		ekPububFromPEMTemplate = tpm2.RSAEKTemplate
		ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: rsaPub.N.Bytes(),
			},
		)
	case *ecdsa.PublicKey:
		ecPub, ok := parsedKey.(*ecdsa.PublicKey)
		require.True(t, ok)
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
	default:
		require.Fail(t, "unknonw public key type %v", pub)
	}

	///  now read the RSA private key to import/export

	tests := []struct {
		name     string
		password string

		hsh     tpm2.TPMAlgID
		alg     string
		crv     tpm2.TPMECCCurve
		keyFile string
	}{
		{"prime256v1", "bar", tpm2.TPMAlgSHA256, "ecc256", tpm2.TPMECCNistP256, "testdata/certs/key_ecc_256.pem"},
		{"secp384r1", "bar", tpm2.TPMAlgSHA384, "ecc384", tpm2.TPMECCNistP384, "testdata/certs/key_ecc_384.pem"},
		{"secp521r1", "bar", tpm2.TPMAlgSHA512, "ecc521", tpm2.TPMECCNistP521, "testdata/certs/key_ecc_521.pem"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kbytes, err := os.ReadFile(tc.keyFile)
			require.NoError(t, err)

			block, _ := pem.Decode(kbytes)
			require.NoError(t, err)

			// Parse the PKCS#1 private key
			privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)

			eccPriv, ok := privateKey.(*ecdsa.PrivateKey)
			require.True(t, ok)

			pk := eccPriv.PublicKey

			var sch tpm2.TPMTECCScheme
			switch tc.alg {
			case "ecc256":
				sch = tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tc.hsh,
						},
					),
				}
			case "ecc384":
				sch = tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tc.hsh,
						},
					),
				}
			case "ecc521":
				sch = tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tc.hsh,
						},
					),
				}
			}

			dupKeyTemplate := tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgECC,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					SignEncrypt:         true,
					FixedTPM:            false,
					FixedParent:         false,
					SensitiveDataOrigin: false,
					UserWithAuth:        false,
				},

				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tc.crv,
						Scheme:  sch,
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

			sens2B := tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgECC,
				AuthValue: tpm2.TPM2BAuth{
					Buffer: []byte(password), // set any userAuth
				},

				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgECC,
					&tpm2.TPM2BECCParameter{Buffer: eccPriv.D.FillBytes(make([]byte, len(eccPriv.D.Bytes())))},
				),
			}

			s, err := Duplicate(ekPububFromPEMTemplate, duplicatepb.Secret_ECC, duplicatepb.Secret_EndorsementRSA, "", dupKeyTemplate, sens2B, nil, false)
			require.NoError(t, err)

			/// now import

			sessionEncryptionRspB, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwrB)
			require.NoError(t, err)
			defer func() {
				_, _ = tpm2.FlushContext{
					FlushHandle: sessionEncryptionRspB.ObjectHandle,
				}.Execute(rwrB)
			}()

			key, err := Import(&TPMConfig{
				TPMDevice:               tpmDeviceB,
				SessionEncryptionHandle: sessionEncryptionRspB.ObjectHandle,
			}, ekHandle, s)
			require.NoError(t, err)

			_, _ = tpm2.FlushContext{
				FlushHandle: sessionEncryptionRspB.ObjectHandle,
			}.Execute(rwrB)
			require.NoError(t, err)

			// now load the key

			_, ekHandleB, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: ekHandleB,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			pubEKB, err := tpm2.ReadPublic{
				ObjectHandle: ekHandleB,
			}.Execute(rwrB)
			require.NoError(t, err)

			load_session, load_session_cleanup, err := tpm2.PolicySession(rwrB, tpm2.TPMAlgSHA256, 16)
			require.NoError(t, err)
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth(nil),
				},
				PolicySession: load_session.Handle(),
				NonceTPM:      load_session.NonceTPM(),
			}.Execute(rwrB)
			require.NoError(t, err)

			regenECCKey, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: ekHandleB,
					Name:   pubEKB.Name,
					Auth:   load_session,
				},
				InPublic:  key.Pubkey,
				InPrivate: key.Privkey,
			}.Execute(rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: regenECCKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			ppub, err := tpm2.ReadPublic{
				ObjectHandle: tpm2.TPMIDHObject(regenECCKey.ObjectHandle),
			}.Execute(rwrB)
			require.NoError(t, err)
			outPub, err := ppub.OutPublic.Contents()
			require.NoError(t, err)
			ecDetail, err := outPub.Parameters.ECCDetail()
			require.NoError(t, err)
			crv, err := ecDetail.CurveID.Curve()
			require.NoError(t, err)

			eccUnique, err := outPub.Unique.ECC()
			require.NoError(t, err)

			eccPubregen := &ecdsa.PublicKey{
				Curve: crv,
				X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
				Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
			}

			require.NoError(t, err)

			require.Equal(t, eccPubregen, &eccPriv.PublicKey)

			stringToSign := "foo"

			b := []byte(stringToSign)

			hh, err := tc.hsh.Hash()
			require.NoError(t, err)

			h := hh.New()
			h.Write(b)
			digest := h.Sum(nil)

			svc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(password), pubEKB.Name, ekHandle)
			require.NoError(t, err)
			or_sess, or_sess_cleanup, err := svc.GetSession()
			require.NoError(t, err)
			defer or_sess_cleanup()

			sign := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: regenECCKey.ObjectHandle,
					Name:   regenECCKey.Name,
					Auth:   or_sess, //tpm2.PasswordAuth(nil),
				},
				Digest: tpm2.TPM2BDigest{
					Buffer: digest[:],
				},
				InScheme: tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSchemeHash{
							HashAlg: tc.hsh,
						},
					),
				},
				Validation: tpm2.TPMTTKHashCheck{
					Tag: tpm2.TPMSTHashCheck,
				},
			}

			eccSign, err := sign.Execute(rwrB)
			require.NoError(t, err)

			ecs, err := eccSign.Signature.Signature.ECDSA()
			require.NoError(t, err)

			x := big.NewInt(0).SetBytes(ecs.SignatureR.Buffer)
			y := big.NewInt(0).SetBytes(ecs.SignatureS.Buffer)

			ok = ecdsa.Verify(eccPubregen, digest[:], x, y)
			require.True(t, ok)

		})
	}

}

func TestDuplicateAES(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	defer tpmDeviceB.Close()

	password := "somepassword"
	// ***** first get the ekpubB

	ekpubPEM, ekHandle, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: ekHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()
	var ekPububFromPEMTemplate tpm2.TPMTPublic
	eblock, _ := pem.Decode(ekpubPEM)
	parsedKey, err := x509.ParsePKIXPublicKey(eblock.Bytes)
	require.NoError(t, err)

	switch pub := parsedKey.(type) {
	case *rsa.PublicKey:
		rsaPub, ok := parsedKey.(*rsa.PublicKey)
		require.True(t, ok)
		ekPububFromPEMTemplate = tpm2.RSAEKTemplate
		ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: rsaPub.N.Bytes(),
			},
		)
	case *ecdsa.PublicKey:
		ecPub, ok := parsedKey.(*ecdsa.PublicKey)
		require.True(t, ok)
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
	default:
		require.Fail(t, "unknonw public key type %v", pub)
	}
	///  now read the RSA private key to import/export
	tests := []struct {
		name string

		alg     tpm2.TPMAlgID
		keyFile string
	}{
		{"cfb_128", tpm2.TPMAlgCFB, "testdata/certs/aes_128.key"},
		{"cfb_256", tpm2.TPMAlgCFB, "testdata/certs/aes_256.key"},
		{"cbc_128", tpm2.TPMAlgCBC, "testdata/certs/aes_128.key"},
		{"ctr_128", tpm2.TPMAlgCTR, "testdata/certs/aes_128.key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// keyFile := "testdata/certs/aes.key"
			kbytes, err := os.ReadFile(tc.keyFile)
			require.NoError(t, err)

			keySensitive, err := hex.DecodeString(string(kbytes))
			require.NoError(t, err)

			sv := make([]byte, 32)
			io.ReadFull(rand.Reader, sv)
			privHash := crypto.SHA256.New()
			privHash.Write(sv)
			privHash.Write(keySensitive)

			dupKeyTemplate := tpm2.TPMTPublic{
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

				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPMSSymCipherParms{
						Sym: tpm2.TPMTSymDefObject{
							Algorithm: tpm2.TPMAlgAES,
							Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tc.alg),
							KeyBits: tpm2.NewTPMUSymKeyBits(
								tpm2.TPMAlgAES,
								tpm2.TPMKeyBits(len(keySensitive)*8),
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

			sens2B := tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgSymCipher,
				AuthValue: tpm2.TPM2BAuth{
					Buffer: []byte(password),
				},
				SeedValue: tpm2.TPM2BDigest{
					Buffer: sv,
				},
				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPM2BSymKey{Buffer: keySensitive},
				),
			}

			s, err := Duplicate(ekPububFromPEMTemplate, duplicatepb.Secret_AES, duplicatepb.Secret_EndorsementRSA, "", dupKeyTemplate, sens2B, nil, false)

			require.NoError(t, err)

			/// now import

			sessionEncryptionRspB, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwrB)
			require.NoError(t, err)
			defer func() {
				_, _ = tpm2.FlushContext{
					FlushHandle: sessionEncryptionRspB.ObjectHandle,
				}.Execute(rwrB)
			}()

			key, err := Import(&TPMConfig{
				TPMDevice:               tpmDeviceB,
				SessionEncryptionHandle: sessionEncryptionRspB.ObjectHandle,
			}, ekHandle, s)
			require.NoError(t, err)

			_, _ = tpm2.FlushContext{
				FlushHandle: sessionEncryptionRspB.ObjectHandle,
			}.Execute(rwrB)
			require.NoError(t, err)

			// now load the key

			_, ekHandleB, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: ekHandleB,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			pubEKB, err := tpm2.ReadPublic{
				ObjectHandle: ekHandleB,
			}.Execute(rwrB)
			require.NoError(t, err)

			load_session, load_session_cleanup, err := tpm2.PolicySession(rwrB, tpm2.TPMAlgSHA256, 16)
			require.NoError(t, err)
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth(nil),
				},
				PolicySession: load_session.Handle(),
				NonceTPM:      load_session.NonceTPM(),
			}.Execute(rwrB)
			require.NoError(t, err)

			regenAESKey, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: ekHandleB,
					Name:   pubEKB.Name,
					Auth:   load_session,
				},
				InPublic:  key.Pubkey,
				InPrivate: key.Privkey,
			}.Execute(rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: regenAESKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			stringToEncrypt := "00000000fooooooo"

			data := []byte(stringToEncrypt)

			iv := make([]byte, aes.BlockSize)
			_, err = io.ReadFull(rand.Reader, iv)
			require.NoError(t, err)

			svc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(password), pubEKB.Name, ekHandle)
			require.NoError(t, err)
			or_sess, or_sess_cleanup, err := svc.GetSession()
			require.NoError(t, err)
			defer or_sess_cleanup()

			keyAuth := tpm2.AuthHandle{
				Handle: regenAESKey.ObjectHandle,
				Name:   regenAESKey.Name,
				Auth:   or_sess, //tpm2.PasswordAuth([]byte(nil)),
			}
			encrypted, err := encryptDecryptSymmetric(rwrB, tc.alg, keyAuth, iv, data, false)
			require.NoError(t, err)

			svc, err = NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(password), pubEKB.Name, ekHandle)
			require.NoError(t, err)
			or_sess, or_sess_cleanup, err = svc.GetSession()
			require.NoError(t, err)
			defer or_sess_cleanup()

			keyAuth = tpm2.AuthHandle{
				Handle: regenAESKey.ObjectHandle,
				Name:   regenAESKey.Name,
				Auth:   or_sess, //tpm2.PasswordAuth([]byte(nil)),
			}

			decrypted, err := encryptDecryptSymmetric(rwrB, tc.alg, keyAuth, iv, encrypted, true)
			require.NoError(t, err)

			require.Equal(t, decrypted, data)
		})
	}

}

func encryptDecryptSymmetric(rwr transport.TPM, mode tpm2.TPMAlgID, keyAuth tpm2.AuthHandle, iv, data []byte, decrypt bool) ([]byte, error) {
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
			Mode:    mode,
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

func TestDuplicateHMAC(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	defer tpmDeviceB.Close()

	password := "somepassword"
	// ***** first get the ekpubB

	ekpubPEM, ekHandle, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: ekHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	var ekPububFromPEMTemplate tpm2.TPMTPublic
	eblock, _ := pem.Decode(ekpubPEM)
	parsedKey, err := x509.ParsePKIXPublicKey(eblock.Bytes)
	require.NoError(t, err)

	switch pub := parsedKey.(type) {
	case *rsa.PublicKey:
		rsaPub, ok := parsedKey.(*rsa.PublicKey)
		require.True(t, ok)
		ekPububFromPEMTemplate = tpm2.RSAEKTemplate
		ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: rsaPub.N.Bytes(),
			},
		)
	case *ecdsa.PublicKey:
		ecPub, ok := parsedKey.(*ecdsa.PublicKey)
		require.True(t, ok)
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
	default:
		require.Fail(t, "unknonw public key type %v", pub)
	}

	tests := []struct {
		name string

		hsh     tpm2.TPMAlgID
		keyFile string
	}{
		{"SHA256", tpm2.TPMAlgSHA256, "testdata/certs/hmac_256.key"},
		{"SHA512", tpm2.TPMAlgSHA256, "testdata/certs/hmac_512.key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			keySensitive, err := os.ReadFile(tc.keyFile)
			require.NoError(t, err)

			sv := make([]byte, 32)
			io.ReadFull(rand.Reader, sv)
			privHash := crypto.SHA256.New()
			privHash.Write(sv)
			privHash.Write(keySensitive)

			dupKeyTemplate := tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgKeyedHash,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					SignEncrypt:         true,
					FixedTPM:            false,
					FixedParent:         false,
					SensitiveDataOrigin: false,
					UserWithAuth:        false,
				},

				Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
					&tpm2.TPMSKeyedHashParms{
						Scheme: tpm2.TPMTKeyedHashScheme{
							Scheme: tpm2.TPMAlgHMAC,
							Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
								&tpm2.TPMSSchemeHMAC{
									HashAlg: tc.hsh,
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

			sens2B := tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgKeyedHash,
				AuthValue: tpm2.TPM2BAuth{
					Buffer: []byte(password), // set any userAuth
				},
				SeedValue: tpm2.TPM2BDigest{
					Buffer: sv,
				},
				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgKeyedHash,
					&tpm2.TPM2BSensitiveData{Buffer: keySensitive},
				),
			}

			s, err := Duplicate(ekPububFromPEMTemplate, duplicatepb.Secret_HMAC, duplicatepb.Secret_EndorsementRSA, "", dupKeyTemplate, sens2B, nil, false)
			// ************************
			require.NoError(t, err)
			/// now import

			sessionEncryptionRspB, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwrB)
			require.NoError(t, err)
			defer func() {
				_, _ = tpm2.FlushContext{
					FlushHandle: sessionEncryptionRspB.ObjectHandle,
				}.Execute(rwrB)
			}()

			key, err := Import(&TPMConfig{
				TPMDevice:               tpmDeviceB,
				SessionEncryptionHandle: sessionEncryptionRspB.ObjectHandle,
			}, tpm2.TPMHandle(ekHandle), s)
			require.NoError(t, err)

			_, _ = tpm2.FlushContext{
				FlushHandle: sessionEncryptionRspB.ObjectHandle,
			}.Execute(rwrB)
			require.NoError(t, err)

			// now load the key

			_, ekHandleB, _, err := getPublicKey(t, tpm2.RSAEKTemplate, rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: ekHandleB,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			pubEKB, err := tpm2.ReadPublic{
				ObjectHandle: ekHandleB,
			}.Execute(rwrB)
			require.NoError(t, err)

			load_session, load_session_cleanup, err := tpm2.PolicySession(rwrB, tpm2.TPMAlgSHA256, 16)
			require.NoError(t, err)
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth(nil),
				},
				PolicySession: load_session.Handle(),
				NonceTPM:      load_session.NonceTPM(),
			}.Execute(rwrB)
			require.NoError(t, err)

			regenHMACKey, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: ekHandleB,
					Name:   pubEKB.Name,
					Auth:   load_session,
				},
				InPublic:  key.Pubkey,
				InPrivate: key.Privkey,
			}.Execute(rwrB)
			require.NoError(t, err)

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: regenHMACKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwrB)
			}()

			flushContextCmd := tpm2.FlushContext{
				FlushHandle: ekHandleB,
			}
			_, _ = flushContextCmd.Execute(rwrB)

			stringToEncrypt := "foo"

			data := []byte(stringToEncrypt)

			/// ********************************
			svc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(password), pubEKB.Name, ekHandle)
			require.NoError(t, err)
			or_sess, or_sess_cleanup, err := svc.GetSession()
			require.NoError(t, err)
			defer or_sess_cleanup()

			objAuth := &tpm2.TPM2BAuth{
				Buffer: []byte(nil),
			}
			hmacBytes, err := thmac(rwrB, data, regenHMACKey.ObjectHandle, regenHMACKey.Name, or_sess, *objAuth)
			require.NoError(t, err)

			// run std hmac and compare

			// echo -n "change this password to a secret" > testdata/certs/hmac_256.key
			// echo -n "change this password to a secret" | xxd -p -c 100
			//    6368616e676520746869732070617373776f726420746f206120736563726574
			// echo -n foo > data.in
			// openssl dgst -sha256 -mac hmac -macopt hexkey:6368616e676520746869732070617373776f726420746f206120736563726574 data.in
			//    HMAC-SHA256(data.in)= 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2

			//expectedMAC := "7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2"
			tch, err := tc.hsh.Hash()
			require.NoError(t, err)

			hmacInstance := stdhmac.New(tch.New, keySensitive)
			_, err = hmacInstance.Write(data)
			require.NoError(t, err)

			expectedMAC := hmacInstance.Sum(nil)

			require.Equal(t, hmacBytes, expectedMAC)
		})
	}
}

func thmac(rwr transport.TPM, data []byte, objHandle tpm2.TPMHandle, objName tpm2.TPM2BName, or_sess tpm2.Session, objAuth tpm2.TPM2BAuth) ([]byte, error) {

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

func TestDuplicatePasswordH2(t *testing.T) {
	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	defer tpmDeviceB.Close()

	h2primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwrB)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: h2primary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	hpub, err := h2primary.OutPublic.Contents()
	require.NoError(t, err)

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: h2primary.ObjectHandle,
	}
	_, err = flushContextCmd.Execute(rwrB)
	require.NoError(t, err)

	// TPM-A

	keyFile := "testdata/certs/key_rsa_2048.pem"
	kbytes, err := os.ReadFile(keyFile)
	require.NoError(t, err)

	block, _ := pem.Decode(kbytes)
	require.NoError(t, err)

	// Parse the PKCS#1 private key
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	require.True(t, ok)

	dupKeyTemplate := tpm2.TPMTPublic{
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
				Exponent: uint32(rsaPrivateKey.PublicKey.E),
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
				Buffer: rsaPrivateKey.PublicKey.N.Bytes(),
			},
		),
	}

	sens2B := tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgRSA,
		AuthValue: tpm2.TPM2BAuth{
			Buffer: []byte(nil), // set any userAuth
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPrivateKeyRSA{Buffer: rsaPrivateKey.Primes[0].Bytes()},
		),
	}

	s, err := Duplicate(*hpub, duplicatepb.Secret_RSA, duplicatepb.Secret_H2, "", dupKeyTemplate, sens2B, nil, false)
	// ************************
	require.NoError(t, err)

	/// now import

	sessionEncryptionRspB, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwrB)
	require.NoError(t, err)
	defer func() {
		_, _ = tpm2.FlushContext{
			FlushHandle: sessionEncryptionRspB.ObjectHandle,
		}.Execute(rwrB)
	}()

	h2primaryload, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: h2primaryload.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	key, err := Import(&TPMConfig{
		TPMDevice:               tpmDeviceB,
		SessionEncryptionHandle: sessionEncryptionRspB.ObjectHandle,
	}, h2primaryload.ObjectHandle, s)
	require.NoError(t, err)

	_, _ = tpm2.FlushContext{
		FlushHandle: sessionEncryptionRspB.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	regenRSAKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: h2primaryload.ObjectHandle,
			Name:   h2primaryload.Name,
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: regenRSAKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	pubregen, err := tpm2.ReadPublic{
		ObjectHandle: regenRSAKey.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	outPubBregen, err := pubregen.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetailBregen, err := outPubBregen.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUniqueBregen, err := outPubBregen.Unique.RSA()
	require.NoError(t, err)

	rsaPubBregen, err := tpm2.RSAPub(rsaDetailBregen, rsaUniqueBregen)
	require.NoError(t, err)

	require.Equal(t, rsaPubBregen, &rsaPrivateKey.PublicKey)

	stringToSign := "foo"

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	encprimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwrB)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: encprimary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	svc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(nil), h2primary.Name, encprimary.ObjectHandle)
	require.NoError(t, err)
	or_sess, or_sess_cleanup, err := svc.GetSession()
	require.NoError(t, err)
	defer or_sess_cleanup()

	sign := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: regenRSAKey.ObjectHandle,
			Name:   regenRSAKey.Name,
			Auth:   or_sess,
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

	_, err = sign.Execute(rwrB)
	require.NoError(t, err)

}

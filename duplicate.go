package tpmcopy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"strconv"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	duplicatepb "github.com/salrashid123/tpmcopy/duplicatepb"

	genkeyutil "github.com/salrashid123/tpm2genkey/util"
)

type TPMConfig struct {
	Debug     bool               // debug logging
	TPMDevice io.ReadWriteCloser // initialized transport for the TPM

	Ownerpw                 []byte         // password for the owner
	SessionEncryptionHandle tpm2.TPMHandle // (optional) handle to use for transit encryption
}

const (
	policySyntaxEnv = "ENABLE_POLICY_SYNTAX" // environment variable to toggle if the policy syntax should be applied to the keyfile
)

// get the public PEM public key for the provide handle
func GetPublicKey(h *TPMConfig, handle tpm2.TPMHandle) ([]byte, error) {

	if handle == 0 {
		return nil, fmt.Errorf("TPM Handle must get set")
	}

	rwr := transport.FromReadWriter(h.TPMDevice)

	ppub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMIDHObject(handle),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("error reading  handle public %v", err)
	}

	pub, err := ppub.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("can't read public object  %v", err)
	}

	// check if the key is either rsa or ecc

	isRSA := true
	_, err = pub.Parameters.RSADetail()
	if err != nil {
		_, err = pub.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("provided handle must be either an RSA or ECC key: %v", err)
		}
		isRSA = false
	}

	var b []byte
	if isRSA {
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("can't read RSA details %v", err)
		}
		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return nil, fmt.Errorf("can't read RSA public unique: %v", err)
		}

		pubKey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, fmt.Errorf("can't read RSA rsapub unique: %v", err)
		}

		b, err = x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("unable to convert RSA  PublicKey: %v", err)
		}
	} else {
		ecDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("failed to get ecc public: %v", err)
		}
		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return nil, fmt.Errorf("failed to get ecc public: %v", err)
		}

		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return nil, fmt.Errorf("failed to get ecc public key: %v", err)
		}

		pubKey := &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
		b, err = x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("unable to convert ECC PublicKey: %v", err)
		}
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		},
	)
	return akPubPEM, nil
}

// create a duplicate of the given key type and template
func Duplicate(ekPububFromPEMTemplate tpm2.TPMTPublic, keyType duplicatepb.Secret_KeyType, parentKeyType duplicatepb.Secret_ParentKeyType, keyName string, dupTemplate tpm2.TPMTPublic, dupSensitive tpm2.TPMTSensitive, pcrMap map[uint][]byte) (duplicatepb.Secret, error) {

	var ap []*keyfile.TPMPolicy
	var ekrsaPub *rsa.PublicKey
	var ekeccPub *ecdsa.PublicKey
	var aeskeybits *tpm2.TPMKeyBits

	ekName, err := tpm2.ObjectName(&ekPububFromPEMTemplate)
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf(" failed to get name from ekPububFromPEMTemplate: %v", err)
	}

	if parentKeyType == duplicatepb.Secret_EndorsementRSA {
		rsaDetailB, err := ekPububFromPEMTemplate.Parameters.RSADetail()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" error getting RSADetail %v ", err)
		}

		rsaUniqueB, err := ekPububFromPEMTemplate.Unique.RSA()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" error getting RSA Unique %v ", err)

		}

		ekrsaPub, err = tpm2.RSAPub(rsaDetailB, rsaUniqueB)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" error getting RSA Publcic key from template %v ", err)
		}

		aeskeybits, err = rsaDetailB.Symmetric.KeyBits.AES()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error getting AESKeybits: %v", err)
		}

	} else {
		ecDetail, err := ekPububFromPEMTemplate.Parameters.ECCDetail()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" Error getting ECCDetail %v ", err)
		}

		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" error getting ECC Curve %v ", err)
		}
		eccUnique, err := ekPububFromPEMTemplate.Unique.ECC()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" error getting ECC Public Key from template %v ", err)
		}

		ekeccPub = &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
		aeskeybits, err = ecDetail.Symmetric.KeyBits.AES()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error getting AESKeybits: %v", err)
		}

	}

	var dupPub []byte
	var dupDup []byte
	var dupSeed []byte
	var pcv []*duplicatepb.PCRS
	var finalPolicyDigest []byte

	if len(pcrMap) > 0 {

		_, pcrs, pcrHash, err := getPCRMap(tpm2.TPMAlgSHA256, pcrMap)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error reading pcrMap %v", err)
		}
		sel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
				},
			},
		}

		papcr := tpm2.PolicyPCR{
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: pcrHash,
			},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
		}

		pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting up NewPolicyCalculator for PolicyAuthValue : %v", err)
		}
		err = papcr.Update(pol)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error updating NewPolicyCalculator for PolicyAuthValue %v", err)
		}
		e, err := genkeyutil.CPBytes(papcr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error creating cpbytes PolicyAuthValue: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyPCR),
			CommandPolicy: e,
		})

		pds := tpm2.PolicyDuplicationSelect{
			NewParentName: *ekName,
		}

		polds, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting up NewPolicyCalculator for policyDuplicateSelect: %v", err)
		}
		err = pds.Update(polds)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error updating NewPolicyCalculator for policyDuplicateSelect: %v", err)
		}
		de, err := genkeyutil.CPBytes(pds)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error creating cpbytes PolicyDuplicationSelect: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyDuplicationSelect),
			CommandPolicy: de,
		})

		por := tpm2.PolicyOr{
			PHashList: tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{tpm2.TPM2BDigest{Buffer: pol.Hash().Digest}, tpm2.TPM2BDigest{Buffer: polds.Hash().Digest}}},
		}

		polOR, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting up NewPolicyCalculator for policyOR: %v", err)
		}
		err = por.Update(polOR)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error updating NewPolicyCalculator for policyOR: %v", err)
		}

		porA, err := genkeyutil.CPBytes(por)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error creating cpbytes PolicyOr: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyOR),
			CommandPolicy: porA,
		})

		finalPolicyDigest = polOR.Hash().Digest

	} else {
		paa := tpm2.PolicyAuthValue{}

		pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting up NewPolicyCalculator for PolicyAuthValue : %v", err)
		}
		err = paa.Update(pol)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error updating NewPolicyCalculator for PolicyAuthValue %v", err)
		}
		e, err := genkeyutil.CPBytes(paa)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error creating cpbytes PolicyAuthValue: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyAuthValue),
			CommandPolicy: e,
		})

		pds := tpm2.PolicyDuplicationSelect{
			NewParentName: *ekName,
		}

		polds, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting up NewPolicyCalculator for policyDuplicateSelect: %v", err)
		}
		err = pds.Update(polds)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error updating NewPolicyCalculator for policyDuplicateSelect: %v", err)
		}
		de, err := genkeyutil.CPBytes(pds)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error creating cpbytes PolicyDuplicationSelect: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyDuplicationSelect),
			CommandPolicy: de,
		})

		por := tpm2.PolicyOr{
			PHashList: tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{tpm2.TPM2BDigest{Buffer: pol.Hash().Digest}, tpm2.TPM2BDigest{Buffer: polds.Hash().Digest}}},
		}

		polOR, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting up NewPolicyCalculator for policyOR: %v", err)
		}
		err = por.Update(polOR)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error updating NewPolicyCalculator for policyOR: %v", err)
		}

		porA, err := genkeyutil.CPBytes(por)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error creating cpbytes PolicyOr: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyOR),
			CommandPolicy: porA,
		})

		finalPolicyDigest = polOR.Hash().Digest
	}

	// createImportBlobHelper

	dupTemplate.AuthPolicy = tpm2.TPM2BDigest{
		Buffer: finalPolicyDigest,
	}

	sens := dupSensitive
	sens2B := tpm2.Marshal(sens)

	packedSecret := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	var seed, encryptedSeed []byte

	h, err := ekPububFromPEMTemplate.NameAlg.Hash()
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf("error getting nameHash from EKTemplate %v", err)
	}

	switch parentKeyType {
	case duplicatepb.Secret_EndorsementRSA:
		//  start createRSASeed
		seedSize := *aeskeybits / 8
		seed = make([]byte, seedSize)
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error getting random for EKRSA %v ", err)
		}

		es, err := rsa.EncryptOAEP(
			h.New(),
			rand.Reader,
			ekrsaPub,
			seed,
			[]byte("DUPLICATE\x00"))
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error  EncryptOAEP: %v", err)
		}

		encryptedSeed, err = tpmutil.Pack(es)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error packing encryptedseed: %v", err)
		}

	case duplicatepb.Secret_EndoresementECC, duplicatepb.Secret_H2:

		ecp, err := ecdsa.GenerateKey(ekeccPub.Curve, rand.Reader)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("failed to generate ecc key %v ", err)
		}
		x := ecp.X
		y := ecp.Y
		priv := ecp.D.Bytes()
		z, _ := ekeccPub.Curve.ScalarMult(ekeccPub.X, ekeccPub.Y, priv)

		create, err := ekPububFromPEMTemplate.NameAlg.Hash()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("failed to get hash from template %v ", err)
		}
		xBytes := eccIntToBytes(ekeccPub.Curve, x)
		seed = tpm2.KDFe(
			h,
			eccIntToBytes(ekeccPub.Curve, z),
			"DUPLICATE",
			xBytes,
			eccIntToBytes(ekeccPub.Curve, ekeccPub.X),
			create.Size()*8)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("failed to create kdfe: %v", err)
		}

		encryptedSeed, err = tpmutil.Pack(tpmutil.U16Bytes(xBytes), tpmutil.U16Bytes(eccIntToBytes(ekeccPub.Curve, y)))
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("failed  to pack  encryptedseed: %v", err)
		}
	default:
		return duplicatepb.Secret{}, fmt.Errorf("failed  to pack  encryptedseed: %v", err)
	}

	name, err := tpm2.ObjectName(&dupTemplate)
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf("failed to get name key: %v", err)
	}

	nameEncoded := name.Buffer

	symSize := int(*aeskeybits)

	h2, err := ekPububFromPEMTemplate.NameAlg.Hash()
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf("failed to get ek.Scheme.Scheme.Hash: %v", err)
	}

	symmetricKey := tpm2.KDFa(
		h2,
		seed,
		"STORAGE",
		nameEncoded,
		/*contextV=*/ nil,
		symSize)
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf("failed to kdfa: %v", err)
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf("failed to get aes cipher: %v", err)
	}
	encryptedSecret := make([]byte, len(packedSecret))
	iv := make([]byte, len(symmetricKey))
	cipher.NewCFBEncrypter(c, iv).XORKeyStream(encryptedSecret, packedSecret)
	// end encryptSecret

	// start createHMAC
	h3, err := ekPububFromPEMTemplate.NameAlg.Hash()
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf("failed ek.Scheme.Scheme.Hash: %v", err)
	}

	macKey := tpm2.KDFa(
		h3,
		seed,
		"INTEGRITY",
		/*contextU=*/ nil,
		/*contextV=*/ nil,
		h3.New().Size()*8)

	mac := hmac.New(func() hash.Hash { return h.New() }, macKey)
	mac.Write(encryptedSecret)
	mac.Write(nameEncoded)
	hmacSum := mac.Sum(nil)
	// end createHMAC

	dup := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: hmacSum})
	dup = append(dup, encryptedSecret...)

	pubEncoded := tpm2.Marshal(&dupTemplate)
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf("failed to get name key: %v", err)
	}
	dupPub = pubEncoded
	dupDup = dup
	dupSeed = encryptedSeed

	_, ok := os.LookupEnv(policySyntaxEnv)
	if !ok {
		ap = nil
	}

	tkey := keyfile.TPMKey{
		Keytype:   keyfile.OIDImportableKey,
		EmptyAuth: true,
		Parent:    tpm2.TPMRHFWOwner,
		Policy:    ap,
		Secret:    tpm2.TPM2BEncryptedSecret{Buffer: dupSeed},
		Privkey:   tpm2.TPM2BPrivate{Buffer: dupDup},
		Pubkey:    tpm2.BytesAs2B[tpm2.TPMTPublic](dupPub),
	}
	if dupSensitive.AuthValue.Buffer != nil {
		tkey.EmptyAuth = false
	}
	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, &tkey)
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf("error encoding keyfile %v", err)
	}
	return duplicatepb.Secret{
		Name:          keyName,
		Version:       1,
		Type:          keyType,
		ParentKeyType: parentKeyType,
		ParentName:    hex.EncodeToString(ekName.Buffer),
		Key:           keyFileBytes.String(),
		Pcrs:          pcv,
	}, nil

}

// import the given duplicate secret into a target tpm
func Import(h *TPMConfig, parentHandle tpm2.TPMHandle, secret duplicatepb.Secret) (keyfile.TPMKey, error) {

	if h.SessionEncryptionHandle == 0 {
		return keyfile.TPMKey{}, fmt.Errorf("error please specify a sessionEncryptionHandle")
	}

	rwr := transport.FromReadWriter(h.TPMDevice)

	// setup parameter encryption
	var sess tpm2.Session

	if h.SessionEncryptionHandle != 0 {
		epub, err := tpm2.ReadPublic{
			ObjectHandle: tpm2.TPMIDHObject(h.SessionEncryptionHandle),
		}.Execute(rwr)
		if err != nil {
			return keyfile.TPMKey{}, fmt.Errorf("error reading encryption handle public %v", err)
		}
		var encryptionPub *tpm2.TPMTPublic
		encryptionPub, err = epub.OutPublic.Contents()
		if err != nil {
			return keyfile.TPMKey{}, fmt.Errorf("error getting session encryption public contents %v", err)
		}

		sess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(h.SessionEncryptionHandle, *encryptionPub))
	} else {
		sess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn))
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: sess.Handle(),
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	kf, err := keyfile.Decode([]byte(secret.Key))
	if err != nil {
		return keyfile.TPMKey{}, fmt.Errorf("unmarshal secret.key %v", err)
	}

	var importResp *tpm2.ImportResponse
	var importCmd tpm2.Import

	if secret.ParentKeyType == duplicatepb.Secret_H2 {

		h2Pub, err := tpm2.ReadPublic{
			ObjectHandle: tpm2.TPMIDHObject(parentHandle),
		}.Execute(rwr)
		if err != nil {
			return keyfile.TPMKey{}, fmt.Errorf("error reading  handle public for handle [0x%s] %v", strconv.FormatUint(uint64(parentHandle), 16), err)
		}
		if secret.ParentName != hex.EncodeToString(h2Pub.Name.Buffer) {
			return keyfile.TPMKey{}, fmt.Errorf("wrapping public key mismatch, expected [%s], got [%s]", secret.ParentName, hex.EncodeToString(h2Pub.Name.Buffer))
		}

		importCmd = tpm2.Import{
			ParentHandle: tpm2.NamedHandle{
				Handle: parentHandle,
				Name:   h2Pub.Name,
			},
			ObjectPublic: kf.Pubkey,
			Duplicate: tpm2.TPM2BPrivate{
				Buffer: kf.Privkey.Buffer,
			},
			InSymSeed: tpm2.TPM2BEncryptedSecret{
				Buffer: kf.Secret.Buffer,
			},
		}
		importResp, err = importCmd.Execute(rwr, sess)
		if err != nil {
			return keyfile.TPMKey{}, fmt.Errorf("...can't run import from H2 createPrimary %v", err)
		}

		// since this is h2 template, the owner in the PEM file needs to be a permanent handle
		parentHandle = tpm2.TPMRHOwner

	} else {
		ekPub, err := tpm2.ReadPublic{
			ObjectHandle: tpm2.TPMIDHObject(parentHandle),
		}.Execute(rwr)
		if err != nil {
			return keyfile.TPMKey{}, fmt.Errorf("error reading  handle public for handle [0x%s] %v", strconv.FormatUint(uint64(parentHandle), 16), err)
		}

		if secret.ParentName != hex.EncodeToString(ekPub.Name.Buffer) {
			return keyfile.TPMKey{}, fmt.Errorf("wrapping public key mismatch, expected [%s], got [%s]", secret.ParentName, hex.EncodeToString(ekPub.Name.Buffer))
		}

		/// import

		importSession, import_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return keyfile.TPMKey{}, fmt.Errorf("setting up trial session: %v", err)
		}
		defer import_session_cleanup()

		_, err = tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
				Auth:   tpm2.PasswordAuth(h.Ownerpw),
			},
			PolicySession: importSession.Handle(),
			NonceTPM:      importSession.NonceTPM(),
		}.Execute(rwr, sess)
		if err != nil {
			return keyfile.TPMKey{}, fmt.Errorf("error setting policy PolicySecret %v", err)
		}

		importCmd = tpm2.Import{
			ParentHandle: tpm2.AuthHandle{
				Handle: parentHandle,
				Name:   ekPub.Name,
				Auth:   importSession,
			},

			ObjectPublic: kf.Pubkey,
			Duplicate: tpm2.TPM2BPrivate{
				Buffer: kf.Privkey.Buffer,
			},
			InSymSeed: tpm2.TPM2BEncryptedSecret{
				Buffer: kf.Secret.Buffer,
			},
		}
		importResp, err = importCmd.Execute(rwr, sess)
		if err != nil {
			return keyfile.TPMKey{}, fmt.Errorf("...can't run Import for EK RSA %v", err)
		}
	}

	kfn := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		importCmd.ObjectPublic,
		importResp.OutPrivate,
		keyfile.WithParent(parentHandle),
		keyfile.WithAuthPolicy(nil),
	)
	kfn.Policy = kf.Policy
	kfn.EmptyAuth = kf.EmptyAuth

	return *kfn, nil
}

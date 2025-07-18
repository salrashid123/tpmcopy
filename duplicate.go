package tpmcopy

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	duplicatepb "github.com/salrashid123/tpmcopy/duplicatepb"
)

type TPMConfig struct {
	Debug     bool               // debug logging
	TPMDevice io.ReadWriteCloser // initialized transport for the TPM

	Ownerpw                 []byte         // password for the owner
	SessionEncryptionHandle tpm2.TPMHandle // (optional) handle to use for transit encryption
}

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
			return nil, fmt.Errorf("failed to get rsa public: %v", err)
		}
		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return nil, fmt.Errorf("failed to get rsa public: %v", err)
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
func Duplicate(h *TPMConfig, ekPububFromPEMTemplate tpm2.TPMTPublic, keyType duplicatepb.Secret_KeyType, keyName string, dupTemplate tpm2.TPMTPublic, dupSensitive tpm2.TPMTSensitive, pcrMap map[uint][]byte) (duplicatepb.Secret, error) {

	if h.SessionEncryptionHandle == 0 {
		return duplicatepb.Secret{}, fmt.Errorf("error please specify a sessionEncryptionHandle")
	}
	rwr := transport.FromReadWriter(h.TPMDevice)

	// setup parameter encryption
	var sess tpm2.Session
	var encryptionPub *tpm2.TPMTPublic
	if h.SessionEncryptionHandle != 0 {
		epub, err := tpm2.ReadPublic{
			ObjectHandle: tpm2.TPMIDHObject(h.SessionEncryptionHandle),
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error reading encryption handle public %v", err)
		}

		encryptionPub, err = epub.OutPublic.Contents()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error getting session encryption public contents %v", err)
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
	// parameter encryption

	ekName, err := tpm2.ObjectName(&ekPububFromPEMTemplate)
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf(" failed to get name key: %v", err)
	}

	// create a generic local primary key
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth(h.Ownerpw),
		},
		//InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
		InPublic: tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr, sess)
	if err != nil {
		return duplicatepb.Secret{}, fmt.Errorf("can't  CreatePrimary %v", err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, _ = flush.Execute(rwr)
	}()

	pcrMap, pcrs, pcrHash, err := getPCRMap(tpm2.TPMAlgSHA256, pcrMap)
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

	var dupPub []byte
	var dupDup []byte
	var dupSeed []byte

	var pcv []*duplicatepb.PCRS
	var userAuth bool
	if len(pcrs) > 0 {
		// create a pcr trial session to get its digest
		pcr_sess_trial, pcr_sess_trial_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(h.SessionEncryptionHandle, *encryptionPub)}...)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("setting up trial session: %v", err)
		}
		defer pcr_sess_trial_cleanup()

		_, err = tpm2.PolicyPCR{
			PolicySession: pcr_sess_trial.Handle(),
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: pcrHash,
			},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error executing PolicyPCR: %v", err)
		}

		// read the digest
		pcrpgd, err := tpm2.PolicyGetDigest{
			PolicySession: pcr_sess_trial.Handle(),
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error executing PolicyGetDigest: %v", err)
		}
		err = pcr_sess_trial_cleanup()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error purging session: %v", err)
		}

		// create a trial session with PolicyDuplicationSelect which stipulates the target systems
		// where this key can get duplicated
		dupselect_sess_trial, dupselect_trial_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(h.SessionEncryptionHandle, *encryptionPub)}...)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("setting up trial session: %v", err)
		}
		defer dupselect_trial_cleanup()

		_, err = tpm2.PolicyDuplicationSelect{
			PolicySession: dupselect_sess_trial.Handle(),
			NewParentName: *ekName,
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting policy duplicationSelect %v", err)
		}

		// get its digest
		dupselpgd, err := tpm2.PolicyGetDigest{
			PolicySession: dupselect_sess_trial.Handle(),
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error executing PolicyGetDigest: %v", err)
		}
		err = dupselect_trial_cleanup()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error purging session: %v", err)
		}

		// create an OR policy which includes the PolicyPCR and PolicyDuplicationSelect digests
		or_sess_trial, or_sess_tiral_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(h.SessionEncryptionHandle, *encryptionPub)}...)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("setting up trial session: %v", err)
		}
		defer or_sess_tiral_cleanup()

		_, err = tpm2.PolicyOr{
			PolicySession: or_sess_trial.Handle(),
			PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd.PolicyDigest}},
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting policyOR %v", err)
		}

		// calculate the OR hash
		or_trial_digest, err := tpm2.PolicyGetDigest{
			PolicySession: or_sess_trial.Handle(),
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error executing PolicyGetDigest: %v", err)
		}
		err = or_sess_tiral_cleanup()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error purging session: %v", err)
		}

		dupTemplate.AuthPolicy = or_trial_digest.PolicyDigest
		sens2B := tpm2.Marshal(dupSensitive)
		l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})
		dupPriv := tpm2.TPM2BPrivate{Buffer: l}
		importResponse, err := tpm2.Import{
			ParentHandle: tpm2.AuthHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
				Auth:   tpm2.PasswordAuth(h.Ownerpw),
			},
			ObjectPublic: tpm2.New2B(dupTemplate),
			Duplicate:    tpm2.TPM2BPrivate{Buffer: dupPriv.Buffer},
		}.Execute(rwr, sess)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" can't import key %v", err)
		}

		loadResponse, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
				Auth:   tpm2.PasswordAuth(h.Ownerpw),
			},
			InPublic:  tpm2.New2B(dupTemplate),
			InPrivate: importResponse.OutPrivate,
		}.Execute(rwr, sess)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" can't load key %v", err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: loadResponse.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		// clear the primary, we don't need it anymore
		flushPrimaryContextCmd := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, _ = flushPrimaryContextCmd.Execute(rwr)

		///

		// load the target EK
		newParentLoad, err := tpm2.LoadExternal{
			Hierarchy: tpm2.TPMRHOwner,
			InPublic:  tpm2.New2B(ekPububFromPEMTemplate),
		}.Execute(rwr, sess)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" newParentLoadcmd load  %v", err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: newParentLoad.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		// // setup a real session with just PolicyDuplicationSelect
		or_sess, aor_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(h.SessionEncryptionHandle, *encryptionPub)}...)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("setting up trial session: %v", err)
		}
		defer aor_cleanup()

		_, err = tpm2.PolicyDuplicationSelect{
			PolicySession: or_sess.Handle(),
			NewParentName: newParentLoad.Name,
			ObjectName:    loadResponse.Name,
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting  PolicyDuplicationSelect %v", err)
		}

		dupselpgd2, err := tpm2.PolicyGetDigest{
			PolicySession: or_sess.Handle(),
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error executing PolicyGetDigest: %v", err)
		}

		// calculate the OR policy using the digest for the PCR and the "real" sessions PolicyDuplicationSelect value
		_, err = tpm2.PolicyOr{
			PolicySession: or_sess.Handle(),
			PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd2.PolicyDigest}},
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting policy PolicyOr %v", err)
		}

		// create the duplicate but set the Auth to the real policy.  Since we used PolicyDuplicationSelect, the
		//  auth will get fulfilled
		duplicateResp, err := tpm2.Duplicate{
			ObjectHandle: tpm2.AuthHandle{
				Handle: loadResponse.ObjectHandle,
				Name:   loadResponse.Name,
				Auth:   or_sess,
			},
			NewParentHandle: tpm2.NamedHandle{
				Handle: newParentLoad.ObjectHandle,
				Name:   newParentLoad.Name,
			},
			Symmetric: tpm2.TPMTSymDef{
				Algorithm: tpm2.TPMAlgNull,
			},
		}.Execute(rwr) // no need to set rsessInOut since the session is encrypted
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("duplicateResp can't crate duplicate %v", err)
		}
		pb := tpm2.New2B(dupTemplate)

		// generate the bytes for the duplication
		dupPub = pb.Bytes()
		dupSeed = duplicateResp.OutSymSeed.Buffer
		dupDup = duplicateResp.Duplicate.Buffer

		for k, v := range pcrMap {
			pcv = append(pcv, &duplicatepb.PCRS{
				Pcr:   int32(k),
				Value: v,
			})
		}

	} else {

		// userAuth
		// first create a trial session which uses PolicyDuplicationSelect to bind
		// the duplication to eh ekPub of the remote TPM
		userAuth = true
		dupselect_sess_trial, dupselect_trial_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(h.SessionEncryptionHandle, *encryptionPub)}...)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("setting up trial session: %v", err)
		}
		defer dupselect_trial_cleanup()

		_, err = tpm2.PolicyDuplicationSelect{
			PolicySession: dupselect_sess_trial.Handle(),
			NewParentName: *ekName,
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error setting policy PolicyDuplicationSelect %v", err)
		}

		pgd, err := tpm2.PolicyGetDigest{
			PolicySession: dupselect_sess_trial.Handle(),
		}.Execute(rwr)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error executing PolicyGetDigest: %v", err)
		}

		err = dupselect_trial_cleanup()
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("error purging session: %v", err)
		}

		dupTemplate.AuthPolicy = pgd.PolicyDigest
		sens2B := tpm2.Marshal(dupSensitive)
		l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})
		dupPriv := tpm2.TPM2BPrivate{Buffer: l}

		importResponse, err := tpm2.Import{
			ParentHandle: tpm2.AuthHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
				Auth:   tpm2.PasswordAuth(h.Ownerpw),
			},
			ObjectPublic: tpm2.New2B(dupTemplate),
			Duplicate:    tpm2.TPM2BPrivate{Buffer: dupPriv.Buffer},
		}.Execute(rwr, sess)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" can't import key %v", err)
		}

		loadResponse, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
				Auth:   tpm2.PasswordAuth(h.Ownerpw),
			},
			InPublic:  tpm2.New2B(dupTemplate),
			InPrivate: importResponse.OutPrivate,
		}.Execute(rwr, sess)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" can't load key %v", err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: loadResponse.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		// clear the primary, we don't need it anymore
		flushPrimaryContextCmd := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, _ = flushPrimaryContextCmd.Execute(rwr)

		///

		// load the target EK
		newParentLoad, err := tpm2.LoadExternal{
			Hierarchy: tpm2.TPMRHOwner,
			InPublic:  tpm2.New2B(ekPububFromPEMTemplate),
		}.Execute(rwr, sess)
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf(" newParentLoadcmd load  %v", err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: newParentLoad.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		// create the duplicate but set the Auth to the real policy.  Since we used PolicyDuplicationSelect, the
		//  auth will get fulfilled
		duplicateResp, err := tpm2.Duplicate{
			ObjectHandle: tpm2.AuthHandle{
				Handle: loadResponse.ObjectHandle,
				Name:   loadResponse.Name,
				Auth: tpm2.Policy(tpm2.TPMAlgSHA256, 16, tpm2.PolicyCallback(func(tpm transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {

					_, err = tpm2.PolicyDuplicationSelect{
						PolicySession: handle,
						NewParentName: newParentLoad.Name,
						ObjectName:    loadResponse.Name,
					}.Execute(rwr)

					if err != nil {
						return err
					}
					return nil
				})),
			},
			NewParentHandle: tpm2.NamedHandle{
				Handle: newParentLoad.ObjectHandle,
				Name:   newParentLoad.Name,
			},
			Symmetric: tpm2.TPMTSymDef{
				Algorithm: tpm2.TPMAlgNull,
			},
		}.Execute(rwr, sess) // no need to set rsessInOut since the session is encrypted
		if err != nil {
			return duplicatepb.Secret{}, fmt.Errorf("duplicateResp can't crate duplicate %v", err)
		}
		pb := tpm2.New2B(dupTemplate)

		// generate the bytes for the duplication
		// generate the bytes for the duplication
		dupPub = pb.Bytes()
		dupSeed = duplicateResp.OutSymSeed.Buffer
		dupDup = duplicateResp.Duplicate.Buffer
	}

	// todo: fill in AuthValue
	// https://github.com/salrashid123/tpm2/tree/master/policy_gen

	return duplicatepb.Secret{
		Name:     keyName,
		Version:  1,
		Type:     keyType,
		UserAuth: userAuth,
		Key: &duplicatepb.Key{
			ParentName: hex.EncodeToString(ekName.Buffer),
			DupPub:     dupPub,
			DupSeed:    dupSeed,
			DupDup:     dupDup,
		},
		Pcrs: pcv,
	}, nil

}

// import the given duplicate secret into a target tpm
func Import(h *TPMConfig, handle tpm2.TPMHandle, secret duplicatepb.Secret, password []byte) (keyfile.TPMKey, error) {

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

	ekPub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMIDHObject(handle),
	}.Execute(rwr)
	if err != nil {
		return keyfile.TPMKey{}, fmt.Errorf("error reading  handle public %v", err)
	}

	if secret.Key.ParentName != hex.EncodeToString(ekPub.Name.Buffer) {
		return keyfile.TPMKey{}, fmt.Errorf("wrapping public key mismatch, expected [%s], got [%s]", secret.Key.ParentName, hex.EncodeToString(ekPub.Name.Buffer))
	}

	/// import

	import_sess, import_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
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
		PolicySession: import_sess.Handle(),
		NonceTPM:      import_sess.NonceTPM(),
	}.Execute(rwr, sess)
	if err != nil {
		return keyfile.TPMKey{}, fmt.Errorf("error setting policy PolicyDuplicationSelect %v", err)
	}

	dupPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](secret.Key.DupPub)
	if err != nil {
		return keyfile.TPMKey{}, fmt.Errorf("unmarshal public %v", err)
	}

	importCmd := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: handle,
			Name:   ekPub.Name,
			Auth:   import_sess,
		},
		ObjectPublic: tpm2.New2B(*dupPub),
		Duplicate: tpm2.TPM2BPrivate{
			Buffer: secret.Key.DupDup,
		},
		InSymSeed: tpm2.TPM2BEncryptedSecret{
			Buffer: secret.Key.DupSeed,
		},
	}

	importResp, err := importCmd.Execute(rwr, sess)
	if err != nil {
		return keyfile.TPMKey{}, fmt.Errorf("...can't run import dup %v", err)
	}

	kf := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		tpm2.New2B(*dupPub),
		importResp.OutPrivate,
		keyfile.WithParent(handle),
		keyfile.WithUserAuth(password),
	)

	return *kf, nil
}

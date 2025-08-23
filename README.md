## tpmcopy:  Transfer  RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)

Utility function you can use to securely copy an `RSA` or `ECC` or `AES` or `HMAC`  **KEY** from your laptop to a remote `Trusted Platform MOdule (TPM)`

Basically, you can transfer a key from your laptop (`local`)  to `TPM-B` such that the key cannot get decrypted or exposed outside of `TPM-B`.  

The key you transfer will not get exposed into user space but can be used to sign/encrypt/decrypt/hmac while always existing _inside_ the destination `TPM`.

Furthermore, you can place TPM based conditions on the transfer and the use of that key on the destination TPM

For examples, you can specify a passphrase or certain `PCR` values must be present on use for the destination key.
Alternativley, if you just want some secret to get transferred securely only to get decrypted in userspace (eg securely transfer raw data as opposed to a TPM-embedded key), see 

* [Go-TPM-Wrapping - Go library and CLI utiity for encrypting data using Trusted Platform Module (TPM)](https://github.com/salrashid123/go-tpm-wrapping)

---

### Overview

At a high level, this utility basically performs [tpm2_duplicate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md) and involves several steps:

If you want to transfer an external `RSA|ECC|AES|HMAC` key _from_  a `local` system  to `TPM-B`, you will need to

1. On `TPM-B`, extract the [Endorsement Public Key](https://trustedcomputinggroup.org/wp-content/uploads/EK-Credential-Profile-For-TPM-Family-2.0-Level-0-V2.5-R1.0_28March2022.pdf) or the [H2 ECC SRK](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)
   Copy the public key to the system from which you want to transfer the secret key (eg, local)

2. On `local`, create the secret `RSA|ECC|AES|HMAC`

3. On `local` use `TPM-B` public key to [duplicate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md) the secret key such that it can only get loaded -inside- `TPM-B`
   The duplicate step will encrypt the external key such that only `TPM-B` can import it.
   The encrypted key is saved as a file which you will need to copy to `TPM-B`

4. On `TPM-B`  [import](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_import.1.md) the duplicated key you  copied from `TPM-A`
   The imported key is saved in TPM encoded PEM format for later use

5. On `TPM-B` use the imported key to sign,encrypt,decrypt,hmac


It is critical to note the key that is transferred carries specific TPM policies which must be fulfilled upon use.  
These policies ensure the key cannot get duplicated beyond the target TPM. Specifically, the keys carry:

* PCR: `tpm2_policyor(tpm2_policypcr | tpm2_policyduplicateselect`
* Password: `tpm2_policyor(tpm2_policyauthvalue | tpm2_policyduplicateselct)`.

For more details, see the section below on [Bound Key Policy](#bound-key-policy)

Furthermore, the `TPM-B` parent must be the Endorsement ECC/RSA key or the H2 Primary from Storage.  No other parent types are currently supported.  A TODO: maybe to supply the `name` of any parent directly to the local system vs deriving it from the public key for known types.

---

| Option | Description |
|:------------|-------------|
| **`-tpm-path`** | Path to the TPM device (default: `/dev/tpmrm0`) |
| **`-mode`** | Operation mode: `publickey duplicate import` (default: ``) |
| **`-keyType`** | type of key to import/export (`rsa ecc aes hmac`) (default: "rsa") |
| **`-out`** | File to write the file to import (default: `""`) |
| **`-in`** | File to read the file to import (default: `""`) |
| **`-pubout`** | Save the imported key as `TPM2B_PUBLIC` (default: `"`) |
| **`-privout`** | Save the imported private as , `TPM2B_PRIVATE` (default: `"`) |
| **`-secret`** | File with secret to duplicate (rsa | ecc | hex encoded symmetric key or hmac pass) (default: `/tmp/key.pem`) |
| **`-password`** | passphrase for the TPM key (default: "") |
| **`-parent`** | parent to to encode the key parent against or load. |
| **`-persistentHandle`** | persistentHandle to save the key to (default `0x81008001` owner) |
| **`-ownerpw`** | passphrase for the TPM owner (default: "") |
| **`-keyName`** | description of the key to annotate (default: "") |
| **`-pcrValues`** | comma separated list of current pcr values to bind the key to (default: "") |
| **`-tpmPublicKeyFile`** | File to write the public key to  (default: ` /tmp/public.pem`) |
| **`-parentKeyType`** | type of the parent Key (`rsa ecc`) (default: "rsa") |
| **`-tpm-session-encrypt-with-name`** | "hex encoded TPM object 'name' to use with an encrypted session" |
| **`-help`** | print usage |

>> This repo is not supported by Google

---

##### References

* [tpm2 key utility](https://github.com/salrashid123/tpm2genkey)
* [Sign, Verify and decode using Google Cloud vTPM Attestation Key and Certificate](https://github.com/salrashid123/gcp-vtpm-ek-ak)
* [TPM based Google Cloud Credential Access Token](https://github.com/salrashid123/oauth2)
* [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)
* [TPM Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-tpm)
* [go-tpm-tools: Transferring RSA and Symmetric keys with GCP vTPMs](https://github.com/salrashid123/gcp_tpm_sealed_keys)

---

## Build

You can use the binary in the [Releases](https://github.com/salrashid123/tpmcopy/releases) page as a standalone cli or load as a library or just build: 

```bash
go build -o tpmcopy cmd/main.go
```

## Usage

To tranfer an `RSA` key from `local` to `TPM-B`

### RSA

To transfer an RSASSA key

```bash
### Local
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out /tmp/key_rsa.pem

### TPM-B
export TPMB="/dev/tpmrm0"
go run cmd/main.go --mode publickey --parentKeyType=rsa_ek -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB
###  copy public.pem to Local

### local
go run cmd/main.go --mode duplicate --keyType=rsa --secret=/tmp/key_rsa.pem \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

###  copy /tmp/out.json to TPM-B

### TPM-B
go run cmd/main.go --mode import --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey.pem  --tpm-path=$TPMB

### test
cd example/
go run rsa/password/main.go --pemFile=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB
```

### ECC

To transfer an `ECC-P256` key

```bash
### Local
openssl genpkey -algorithm ec -pkeyopt  ec_paramgen_curve:P-256  -out /tmp/key_ecc.pem

### TPM-B
export TPMB="/dev/tpmrm0"

go run cmd/main.go --mode publickey --parentKeyType=rsa_ek -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB
###  copy public.pem to Local

## Password
go run cmd/main.go --mode duplicate --keyType=ecc --secret=/tmp/key_ecc.pem \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

###  copy /tmp/out.json to TPM-B

### TPM-B
go run cmd/main.go --mode import --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey.pem  --tpm-path=$TPMB

### test
cd example/
go run ecc/password/main.go --pemFile=/tmp/tpmkey.pem --password=bar --tpm-path=$TPMB
```

### AES

To transfer `AES-128 CFB`

```bash
### Local
echo -n "46be0927a4f86577f17ce6d10bc6aa61" > /tmp/aes.key

### TPM-B
export TPMB="/dev/tpmrm0"

go run cmd/main.go --mode publickey --parentKeyType=rsa_ek -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB

###  copy  public.pem to local

### Local
go run cmd/main.go --mode duplicate --keyType=aes --secret=/tmp/aes.key \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

###  copy /tmp/out.json to TPM-B

### TPM-B
go run cmd/main.go --mode import --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey.pem  --tpm-path=$TPMB

### test
cd example/
go run aes/password/main.go --pemFile=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB
```

### HMAC

To transfer an `HMAC 256` key,

```bash
### Local
echo -n "change this password to a secret" > /tmp/hmac.key

### TPM-B
export TPMB="/dev/tpmrm0"

go run cmd/main.go --mode publickey --parentKeyType=rsa_ek -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB
###  copy public.pem to Local

### loal
go run cmd/main.go --mode duplicate --keyType=hmac --secret=/tmp/hmac.key \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

###  copy /tmp/out.json to TPM-B

### TPM-B
go run cmd/main.go --mode import --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey.pem  --tpm-path=$TPMB

### test
cd example/
go run hmac/password/main.go --pemFile=/tmp/tpmkey.pem --password=bar --tpm-path=$TPMB
```

---

### Bound Key Policy

Each key that is exported to `TPM-B` is bound using TPM Policies which ensure the key cannot be duplicated further.

The specific base policy applied is [PolicyDuplicateSelect](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_policyduplicationselect.1.md) which ensures the key can only exist on the target TPM and cannot get exported further.  For more information, see [Transfer TPM based key using PCR policy](https://gist.github.com/salrashid123/a61e09684c5d59440834d91241627458)

Furthermore, they key will be bound using [tpm2_policyauthvalue](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_policyauthvalue.1.md) for password and [tpm2_policypcr](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_policypcr.1.md) for PCR.

Since the key is always bound via policy, the [UserWithAuth](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf) flag is always CLEAR (false)

"UserWithAuth: this attribute refers to key use policy and indicates that the object's authValue may be used to
provide the USER role authorizations for the object. If this attribute is CLEAR, then USER role authorizations may
only be provided by satisfying the object's authPolicy in a policy session. Refer to section 3.10 for more details."

Essentially, when you use the duplicated key on the destination, you need to replay

- Password: `tpm2_policyor(tpm2_policyauthvalue, tpm2_policyduplicateselect)` and specify the final `PolicySession` with the passphrase

- PCR: `tpm2_policyor(tpm2_policypcr, tpm2_policyduplicateselect)`

and when the parent is loaded, since by default its the RSA or ECC Endorsement, you need to use `tpm2_policysecret`

To help with construction of the policy session in go, you can use the utility functions here:

- `Password`

```golang
import (
	tpmcopy "github.com/salrashid123/tpmcopy"
)
	// for password and with the parent name as primaryKey.Name:
	tc, err := tpmcopy.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(*password), primaryKey.Name)
	or_sess, or_cleanup, err := tc.GetSession()
	defer or_cleanup()
```

- `PCR`

```golang
import (
	tpmcopy "github.com/salrashid123/tpmcopy"
)
// for pcr's bound to bank 23 and with the parent name as primaryKey.Name:
	se, err := tpmcopy.NewPCRAndDuplicateSelectSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uint(23)),
		},
	}, nil, primaryKey.Name)
	or_sess, or_cleanup, err := se.GetSession()

	defer or_cleanup()
```

For python, you will need to implement both policies as shown [here](https://github.com/salrashid123/cloud_auth_tpm?tab=readme-ov-file#policyauthvalue-and-policyduplicateselect)


### Password Policy

If you want to bind the key to a passphrase

```bash
### local, generate RSA-SSA key
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out /tmp/key_rsa.pem


### TPM-B
export TPMB="/dev/tpmrm0"

go run cmd/main.go --mode publickey --parentKeyType=rsa_ek -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB

# Alternatively, you can use `tpm2_tools`:
# tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub
# tpm2_readpublic -c /tmp/ek.ctx -o /tmp/public.pem -f PEM -n /tmp/ek.name 
# ## or extract the ekcert x509 
# tpm2_getekcertificate -X -o EKCert.bin
# openssl x509 -in EKCert.bin -inform DER -noout -text

# copy `public.pem` to `local`

### local
go run cmd/main.go --mode duplicate  --secret=/tmp/key_rsa.pem --keyType=rsa \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json
# copy `/tmp/out.json` to `TPM-B`

## TPM-B
go run cmd/main.go --mode import --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey.pem  --tpm-path=$TPMB

cd example/
go run rsa/password/main.go --pemFile=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB
```

### PCR Policy

If you wanted to use a PCR policy like one that enforces that to use the key `TPM-B` must have `pcr 23=f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b`

```bash
## TPM-B
go run cmd/main.go --mode publickey --parentKeyType=rsa_ek -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB
### copy `public.pem` to `Local`

$ tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l

$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B


### local
go run cmd/main.go --mode duplicate --keyType=rsa \
   --secret=/tmp/key_rsa.pem  --pcrValues=23:f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b \
   -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json
#copy `/tmp/out.json` to `TPM-B`

go run cmd/main.go --mode import --in=/tmp/out.json --out=/tmp/tpmkey.pem --tpm-path=$TPMB

### test
cd example
### sign directly
go run rsa/pcr/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB
### using crypto.Signer
go run rsa/signer_pcr/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB
```

### Using EK Parent

The examples above all use `RSAEK` parent, if you want to generate and use an EK ECC parent

```bash
go run cmd/main.go --mode publickey --parentKeyType=ecc_ek \
   -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB

go run cmd/main.go --mode duplicate  --secret=/tmp/key_rsa.pem \
   --keyType=rsa --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json 

go run cmd/main.go --mode import --parentKeyType=ecc_ek \
   --in=/tmp/out.json --out=/tmp/tpmkey.pem  --tpm-path=$TPMB

cd example/
go run rsa/password/main.go --pemFile=/tmp/tpmkey.pem \
   --password=bar --parentKeyType=ecc_ek --tpm-path=$TPMB
```


### Using H2 Parent

The examples above all use EK RSA/ECC parent, if you want to use the [H2 profile](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)

```bash
go run cmd/main.go --mode publickey --parentKeyType=h2 \
   -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB

go run cmd/main.go --mode duplicate --parentKeyType=h2 --secret=/tmp/key_rsa.pem \
   --keyType=rsa --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json 

go run cmd/main.go --mode import --parentKeyType=h2  \
   --in=/tmp/out.json --out=/tmp/tpmkey.pem --pubout=/tmp/pub.dat --privout=/tmp/priv.dat \
    --tpm-path=$TPMB

cd example/
go run rsa/persistent_h2_parent/main.go --pemFile=/tmp/tpmkey.pem \
   --password=bar  --tpm-path=$TPMB
```

### TPM2_TOOLS compatibility

If you wanted to use `tpm2_tools` on the key imported to `TPM-B`, then use the `--pubout=` and `--privout=` parameters when importing.

What that'll do is save the key as `[TPM2B_PUBLIC, TPM2B_PRIVATE]`

For example, the follwoing will import the password or pcr policy encoded files and use tpm2_tools to perform further operations.

on `TPM-B`, save the ek (and optionallhy as a persistent handle)

```bash
cd /tmp/
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_readpublic -c ek.ctx -o ek.pem -f PEM -n ek.name
```

transfer the key using `ek.pem` from local then when running `import` on TPM-B, specify the output pub/private part

```bash
go run cmd/main.go --mode import --parentKeyType=rsa_ek \
   --pubout=/tmp/pub.dat --privout=/tmp/priv.dat --in=/tmp/out.json \
   --out=/tmp/tpmkey.pem --tpm-path=$TPMB
```

If the key had a policy password:

```bash
### load
cd /tmp/
tpm2 flushcontext -t
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement
tpm2_load -C ek.ctx -c key.ctx -u pub.dat -r priv.dat --auth session:session.ctx

## regenerate the full policy
tpm2_startauthsession -S sessionA.dat --policy-session
tpm2_policyduplicationselect -S sessionA.dat  -N ek.name -L policyA_dupselect.dat 
tpm2_flushcontext sessionA.dat
rm sessionA.dat

tpm2_startauthsession -S sessionA.dat --policy-session
tpm2_policyauthvalue -S sessionA.dat  -L policyA_auth.dat 

echo -n foo > /tmp/file.txt
tpm2_policyor -S sessionA.dat -L policyA_or.dat sha256:policyA_auth.dat,policyA_dupselect.dat 
tpm2_sign -c key.ctx -g sha256  -f plain  -p"session:sessionA.dat+bar"  -o sig.rss  /tmp/file.txt
```

If the key had a pcr policy

```bash
### load
cd /tmp/
tpm2 flushcontext -t
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement
tpm2_load -C ek.ctx -c key.ctx -u pub.dat -r priv.dat --auth session:session.ctx

## regenerate the full policy
tpm2_startauthsession -S sessionA.dat --policy-session
tpm2_policyduplicationselect -S sessionA.dat  -N ek.name -L policyA_dupselect.dat 
tpm2_flushcontext sessionA.dat
rm sessionA.dat

tpm2_startauthsession -S sessionA.dat --policy-session
tpm2_policypcr -S sessionA.dat -l "sha256:23" -f pcr23_valA.bin -L policyA_pcr.dat 
tpm2_policyor -S sessionA.dat -L policyA_or.dat sha256:policyA_pcr.dat,policyA_dupselect.dat 

### test sign
echo -n foo >/tmp/file.txt
tpm2_sign -c key.ctx -g sha256 -f plain  -o signB.raw /tmp/file.txt -p "session:sessionA.dat" 
rm sessionA.dat
```

For  an `H2`  primary, the steps to sign with password would be

```bash
# ## create H2 Template
printf '\x00\x00' > /tmp/unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
     -c primary.ctx \
     -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat
tpm2_readpublic -c /tmp/primary.ctx -o /tmp/public.pem -f PEM -n /tmp/primary.name 

tpm2 flushcontext -t
tpm2_load -C /tmp/primary.ctx -c /tmp/key.ctx -u /tmp/pub.dat -r /tmp/priv.dat 

## regenerate the full policy
tpm2_startauthsession -S sessionA.dat --policy-session
tpm2_policyduplicationselect -S sessionA.dat  -N/tmp/primary.name  -L policyA_dupselect.dat 
tpm2_flushcontext sessionA.dat
rm sessionA.dat

tpm2_startauthsession -S sessionA.dat --policy-session
tpm2_policyauthvalue -S sessionA.dat  -L policyA_auth.dat 

echo -n "foo" > /tmp/file.txt
tpm2_policyor -S sessionA.dat -L policyA_or.dat sha256:policyA_auth.dat,policyA_dupselect.dat 
tpm2_sign -c key.ctx -g sha256  -f plain  -p"session:sessionA.dat+bar"  -o sig.rss  /tmp/file.txt
```


### Parent persistent handle

If you want to encode the PEM key with a preset persistent handle parent, then during import specify the `-parentpersistentHandle=` flag:

For example, the following will create a key on `TPM-B` and persist it to `0x81008001`.  

From there, you can import the key and and encode the parent into the PEM file directly

```bash
## TPM-B
tpm2_getcap handles-persistent
tpm2_evictcontrol -C o -c 0x81008001
tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub 
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_evictcontrol -c /tmp/ek.ctx 0x81008001
tpm2_readpublic -c /tmp/ek.ctx -o /tmp/public.pem -f PEM -n ek.name -Q
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

## Local
go run cmd/main.go --mode duplicate  --secret=/tmp/key_rsa.pem --keyType=rsa \
    --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

## TPM-B
go run cmd/main.go --mode import --parentKeyType=rsa_ek --password=bar \
   --in=/tmp/out.json  --pubout=/tmp/pub.dat --privout=/tmp/priv.dat  \
   --out=/tmp/tpmkey.pem --parentpersistentHandle=0x81008001  --tpm-path=$TPMB

$ openssl asn1parse -in  /tmp/tpmkey.pem

    0:d=0  hl=4 l= 565 cons: SEQUENCE          
    4:d=1  hl=2 l=   6 prim: OBJECT            :2.23.133.10.1.3
   12:d=1  hl=2 l=   3 cons: cont [ 0 ]        
   14:d=2  hl=2 l=   1 prim: BOOLEAN           :255
   17:d=1  hl=2 l=   5 prim: INTEGER           :81008001   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
   24:d=1  hl=4 l= 314 prim: OCTET STRING      [HEX DUMP]:01380001000B0004000000207487CF644F9B7D548C7CEF7D...
  342:d=1  hl=3 l= 224 prim: OCTET STRING      [HEX DUMP]:00DE0020742AC11B...
```

then run the following sample:  note that the "parent" is read in from the PEM file and initialized automatically

```bash
cd example/
go run rsa/persistent_parent/main.go --pemFile=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB
```

### Key persistent handle

If you want to persist the actual key into NV:

```bash
# tpm-b
go run cmd/main.go --mode publickey --parentKeyType=rsa_ek -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB

# local
go run cmd/main.go --mode duplicate  \
   --secret=/tmp/key_rsa.pem --keyType=rsa \
    --password=bar -tpmPublicKeyFile=/tmp/public.pem \
     -out=/tmp/out.json 

# tpm-b
go run cmd/main.go --mode import \
   --pubout=/tmp/pub.dat --privout=/tmp/priv.dat --in=/tmp/out.json \
   --out=/tmp/tpmkey.pem --tpm-path=$TPMB

### then load
go run cmd/main.go --mode evict \
    --persistentHandle=0x81008001 \
   --in=/tmp/tpmkey.pem --tpm-path=$TPMB

## or using tpm2_tools:
# tpm2_createek -c ek.ctx -G rsa -u ek.pub 
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

# tpm2 startauthsession --session session.ctx --policy-session
# tpm2 policysecret --session session.ctx --object-context endorsement
# tpm2_load -C ek.ctx -c key.ctx -u pub.dat -r priv.dat --auth session:session.ctx
# tpm2_evictcontrol -c key.ctx 0x81008001

go run rsa/persistent_key/main.go --persistentHandle=0x81008001 --password=bar  --tpm-path=$TPMB
```

### Openssl compatiblity

Note that while openssl does have a tpm2 provider, the default CLI does not support complex policy statements bound to keys.

For example, with openssl is limited to basic auth constructors as described [here]](https://github.com/tpm2-software/tpm2-openssl/blob/master/docs/keys.md) 

Since keys transferred by this utility uses more complex policies, you can't really use openssl (but you can use `tpm2_tools`)

```bash
export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"

### assume tpmkey.pem is an rsa key with password using the H2 primary
openssl asn1parse -in  /tmp/tpmkey.pem

export PASSWORD=bar
openssl rsa -provider tpm2 -provider default   -in /tmp/tpmkey.pem -passin env:PASSWORD -text

### this will throw an error since no auth valu is bound to the key
echo -n "foo" >/tmp/data.txt
openssl dgst -sha256 -binary -out /tmp/data.hash /tmp/data.txt
openssl  pkeyutl -provider tpm2 -provider default \
   -sign -inkey /tmp/tpmkey.pem  -passin env:PASSWORD   -in /tmp/data.hash -out /tmp/signature.sig
   #  --pkeyopt user-auth:bar
```

### Session Encryption

Each operation uses [encrypted sessions](https://trustedcomputinggroup.org/wp-content/uploads/TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation_8May23-3.pdf) by default and interrogates the TPM for the current EK directly.

If for whatever reason you want to specify the "name" of the EK to to use, set the `--tpm-session-encrypt-with-name=` parameter shown below

```bash
# for tpmB
tpm2_createek -c /tmp/primaryB.ctx -G rsa  -Q
tpm2_readpublic -c /tmp/primaryB.ctx -o /tmp/ekpubB.pem -n /tmp/ekpubBname.bin -f PEM -Q
xxd -p -c 100 /tmp/ekpubBname.bin 
   000b47ab97fdda365cbb86a37548e38468f72e8baccc633cffc42402183679956608

# Then use the hex value returned in the --tpm-session-encrypt-with-name= argument.
   --tpm-session-encrypt-with-name=000b47ab97fdda365cbb86a37548e38468f72e8baccc633cffc42402183679956608
```

### Key Formats

This utility encodes the key to transfer as protobuf during the `Duplicate()` step

```proto
syntax = "proto3";

package duplicatepb;

option go_package = "github.com/salrashid123/go-tpm-wrapping/tpmwrappb";

message Secret {
  string name = 1;
  int32 version = 2;
  KeyType type = 3; 
  enum KeyType {
    ECC = 0;
    RSA = 1;
    HMAC = 2;
    AES = 3;        
  }
  ParentKeyType parentKeyType = 4;
  enum ParentKeyType {
    EndoresementECC = 0;
    EndorsementRSA = 1;
    H2 = 2;    
  }  
  repeated PCRS pcrs = 5;  
  string key = 6;
  string parentName = 7;
}

message PCRS {
  int32 pcr = 1;
  bytes value = 2;
}
```

So an output file may look like:

```json
{
  "version": 1,
  "type": "RSA",
  "parentKeyType": "EndorsementRSA",
  "key": "-----BEGIN TSS2 PRIVATE KEY-----\nMIIDowYGZ4EFCgEEoYGWMIGTMAqgBAICAWuhAgQAMDGgBAICAYihKQQnAAAAIgAL\nTTWiK01Z+KGkuImOvdG/WUm/oz/Lcb2Z4Jhmyw1YOEsAMFKgBAICAXGhSgRIAAAA\nAgAgj80haauSaU4MYz8at3KEK4JBu8ICiJgfx6we3cH92w4AIG4KC9eaWaph5FAK\nm5HsPBnfHpV1KLWu/ngsdFGgGmuyooIBBgSCAQIBAMOl4GvDGXWAz2Z3W/NNwjd9\n1dFnqKD4FMtm1TlVsptk1hVSdzZ6C0cut3u15LiekeJZwWmFpOyiuJr/lV3cIjKv\naUlq+a3DjcvBPhcYC8Y20J+JFsLujekDOnrDzc6OrTvM8qoXMLJenYmwCAHtdN+0\nH/5s5SeZpDsVCOZZWDfRJLh/F3oM5f5R1VRElyHrx7rbrduLgkqh5j7kCAnC+fet\n1IpSSW55CiwecyHq7ewqqjH9pXLwrMu5DTxUr4OLiuQQD+JISFyLWZI8E06HqzMh\nXT1vyU9J6aQ+hIUQdbFvh639+QyCj/SL3tdqW59/nHbwfxm8MeQxG9Sx0/fPiLkC\nBEAAAUAEggE6ATgAAQALAAQAAAAgtzGhqUcZ8m14fqMMDjocDbzpInzeMioNYjn1\nVKVXqI0AEAAUAAsIAAABAAEBAOopWu7BnpqZMH04VfA6o2SXtlrGHSMPUBducP26\n+eTTPXy0Y4fHOw/qWyYsnzLCcySiZ1sM/vx1mUcQLeyf/u6y1FRPAdv1RX+Bzzvm\nAwnSqyttFqOwfUnu1AFLh7MR/wwqgGL2iBTHuDbXPtzK2IrjqevTwnfLJke9dW4K\nSWdxcEPxMz1mUdV0N4wgIw7NeDp3R8vRS+6MY9IgRiepuZjgOWkjRG50wCw60By1\nujsOrvG6JIFxb2yXHFJ7XyY7r/cgkA0pWUeTKemNMSTPNyEpHlusKi166RwuFI9O\nVI2aS/ME5dsNPJGGuuzwcTK59AZzgwYuNK2lMU2w4fLXGqcEgbEArwAgm/YdhGaF\nigcO0yJEqphb9bitPf8ZJ7DbicHeOt6shx4hTyDG6hgT/RVwMjPN5wRgRZuZfcKR\n0V67QDN9elXn0grU4vk3uDulNP+bePVPHmDE3dJ8kZUp4VYn167PFStPu7+r+okl\nuOAKCjfy71yu6OG73epxdzIXvuTAjuY/zc1AKZqeSonTWHZq4R2whynIpSDFZ6Jh\nehLs1g4RBZpyUQ1PItng8mHJl1Q10OY=\n-----END TSS2 PRIVATE KEY-----\n",
  "parentName": "000b4d35a22b4d59f8a1a4b8898ebdd1bf5949bfa33fcb71bd99e09866cb0d58384b"
}
```

where the `parentName` is actually the duplicating parents 'name' on `TPM-B`:

```bash
$ xxd -p -c 100 /tmp/ek.name 
000bbc0c7f8b565f09e4614624fa6f46ece235c9904d47050e8a8dd466ac9b96d49b
```

As mentioned, the `Import()` function saves the imported using in two ways:

1.  `--out=` parameter saves the imported key as [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html) which is the format openssl (mostly) follows.  However, to use this you need to specify the parent as the endorsement RSA key and not the H2 tepmplate.

2. `--pubout=` and `--privout=` parameters saves they key in raw formats which can be used with `tpm2_tools`


---

#### TPMPolicy Syntax PEM Encoding

If you want to encode the policies into the PEM file based on the __draft__ [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-key-policy-specification), then set `ENABLE_POLICY_SYNTAX` environment variable to any value during the duplicate and import steps.

Please note that it the specs are still draft and is incompatible with the PEM format used by openssl

Anyway, the big advantage of this encoding is the PEM file describes the steps to generate the policy itself and execute them.

For example, see the link here on how to [manually generate](https://github.com/salrashid123/tpm2/tree/master/policy_gen) the policies and  use [policySyntax utility](https://github.com/salrashid123/tpm2genkey/tree/main?tab=readme-ov-file#policy-command-parameters).

In the following note that the same codebase will execute the both types of policies in `keyfile_policy/main.go`:

- PolicyAuthValue

For auth value, the following will generate a key with the syntax variables already baked in
```bash
export ENABLE_POLICY_SYNTAX=1
go run cmd/main.go --mode publickey --parentKeyType=rsa_ek \
    -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB

go run cmd/main.go --mode duplicate \
   --keyType=aes --secret=/tmp/aes.key  \
     --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json 

tpm2_evictcontrol -c 0x81008000
go run cmd/main.go  --mode import \
   --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey_auth.pem  --tpm-path=$TPMB

tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l

cd example/
go run keyfile_policy/main.go --pemFile=/tmp/tpmkey_auth.pem --tpm-path=$TPMB --password=bar
```

- PolicyPCR

```bash
export ENABLE_POLICY_SYNTAX=1
go run cmd/main.go --mode publickey --parentKeyType=rsa_ek \
    -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB


go run cmd/main.go --mode duplicate --keyType=aes    --secret=/tmp/aes.key  \
     --pcrValues=23:f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b  \
      -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

go run cmd/main.go --mode import --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey_pcr.pem --tpm-path=$TPMB

cd example/
go run keyfile_policy/main.go --pemFile=/tmp/tpmkey_pcr.pem --tpm-path=$TPMB
```

the specific PEM files generated has the polices encode into it itself.

Note that the command code for `PolicyDuplicateSelect=0x00000188`, `TPMCCPolicyOR=0x00000171`, `TPMCCPolicyPCR=0x0000017F`

for authvalue 

```bash
$ openssl asn1parse -in  /tmp/tpmkey_auth.pem 
    0:d=0  hl=4 l= 406 cons: SEQUENCE          
    4:d=1  hl=2 l=   6 prim: OBJECT            :2.23.133.10.1.3
   12:d=1  hl=2 l=   3 cons: cont [ 0 ]        
   14:d=2  hl=2 l=   1 prim: BOOLEAN           :255
   17:d=1  hl=3 l= 150 cons: cont [ 1 ]        
   20:d=2  hl=3 l= 147 cons: SEQUENCE          
   23:d=3  hl=2 l=  10 cons: SEQUENCE          
   25:d=4  hl=2 l=   4 cons: cont [ 0 ]        
   27:d=5  hl=2 l=   2 prim: INTEGER           :016B
   31:d=4  hl=2 l=   2 cons: cont [ 1 ]        
   33:d=5  hl=2 l=   0 prim: OCTET STRING      
   35:d=3  hl=2 l=  49 cons: SEQUENCE          
   37:d=4  hl=2 l=   4 cons: cont [ 0 ]        
   39:d=5  hl=2 l=   2 prim: INTEGER           :0188
   43:d=4  hl=2 l=  41 cons: cont [ 1 ]        
   45:d=5  hl=2 l=  39 prim: OCTET STRING      [HEX DUMP]:00000022000B75CE518FE809BFF11C7C3575FB50B943F9EFC3E4C3E0FA4AC3AD796D7DF66DE700
   86:d=3  hl=2 l=  82 cons: SEQUENCE          
   88:d=4  hl=2 l=   4 cons: cont [ 0 ]        
   90:d=5  hl=2 l=   2 prim: INTEGER           :0171
   94:d=4  hl=2 l=  74 cons: cont [ 1 ]        
   96:d=5  hl=2 l=  72 prim: OCTET STRING      [HEX DUMP]:0000000200208FCD2169AB92694E0C633F1AB772842B8241BBC20288981FC7AC1EDDC1FDDB0E0020E6613C6F3F14B6A9C8613FA7D2766BAB170C6E477BB047C5E10928DA897FCB1D
  170:d=1  hl=2 l=   5 prim: INTEGER           :81008000
  177:d=1  hl=2 l=  84 prim: OCTET STRING      [HEX DUMP]:00520025000B000600000020B27A9BE905FD3C543969DF3965EA3B62F554DCB20681BC484E90FAF03FA6E04300060080004300206D1078F0CF8B17C99CD183C71D3E0F29F62FB655B97EC1135832EAFDDB795FF7
  263:d=1  hl=3 l= 144 prim: OCTET STRING      [HEX DUMP]:008E0020F99928C2177F50253A7F8568EC7B14CB1A39C538B3CF4AC83A031257857355EE0010E7A442207E6488A97D046687B925135F5A4F579FA4E4120A2BC274B568DA75EAF2D24299EA17EF2B3132EF39BB64FB9CFF83E772B1FEF2916D0BB3283322B7A4EC809DB0F5229232C5D8EA4A858AADC17D8889A7327A589DFE9560C335D843C725CD21ACD441ED8ACA17
```

for PCR:

```bash
$ openssl asn1parse -in  /tmp/tpmkey_pcr.pem 
    0:d=0  hl=4 l= 450 cons: SEQUENCE          
    4:d=1  hl=2 l=   6 prim: OBJECT            :2.23.133.10.1.3
   12:d=1  hl=2 l=   3 cons: cont [ 0 ]        
   14:d=2  hl=2 l=   1 prim: BOOLEAN           :255
   17:d=1  hl=3 l= 194 cons: cont [ 1 ]        
   20:d=2  hl=3 l= 191 cons: SEQUENCE          
   23:d=3  hl=2 l=  54 cons: SEQUENCE          
   25:d=4  hl=2 l=   4 cons: cont [ 0 ]        
   27:d=5  hl=2 l=   2 prim: INTEGER           :017F
   31:d=4  hl=2 l=  46 cons: cont [ 1 ]        
   33:d=5  hl=2 l=  44 prim: OCTET STRING      [HEX DUMP]:0020E2F61C3F71D1DEFD3FA999DFA36953755C690689799962B48BEBD836974E8CF900000001000B03000080
   79:d=3  hl=2 l=  49 cons: SEQUENCE          
   81:d=4  hl=2 l=   4 cons: cont [ 0 ]        
   83:d=5  hl=2 l=   2 prim: INTEGER           :0188
   87:d=4  hl=2 l=  41 cons: cont [ 1 ]        
   89:d=5  hl=2 l=  39 prim: OCTET STRING      [HEX DUMP]:00000022000B75CE518FE809BFF11C7C3575FB50B943F9EFC3E4C3E0FA4AC3AD796D7DF66DE700
  130:d=3  hl=2 l=  82 cons: SEQUENCE          
  132:d=4  hl=2 l=   4 cons: cont [ 0 ]        
  134:d=5  hl=2 l=   2 prim: INTEGER           :0171
  138:d=4  hl=2 l=  74 cons: cont [ 1 ]        
  140:d=5  hl=2 l=  72 prim: OCTET STRING      [HEX DUMP]:0000000200202094289099C2CB180F28F99C71C8D681123935F7330BDAE5AA1AE1E09F0FE5320020E6613C6F3F14B6A9C8613FA7D2766BAB170C6E477BB047C5E10928DA897FCB1D
  214:d=1  hl=2 l=   5 prim: INTEGER           :81008000
  221:d=1  hl=2 l=  84 prim: OCTET STRING      [HEX DUMP]:00520025000B000600000020114DE1F5BD4B2EC1AA51DE81CA4CEE5EB7B34FD338DCFB0D635F7F65DB56DBF80006008000430020237668CD3AF2827B9A590B32EAA8056226DB1C0D89000E403845AE13C4E35240
  307:d=1  hl=3 l= 144 prim: OCTET STRING      [HEX DUMP]:008E002034CC17FD41CE5414923D8C75624E746276809068E34EF06A2DBBC933004A2E900010EEDBD95BE8D7746EF004BC0DA7CE289B3EEC0FCDC969ADD1D3DC4122FC79BF72F02D2DD9DE11171767FF3979ABA236BC8BF27914B682AFDA920802CD10297594E1A5094A9936AE6CAFE16DDCE1170E65F7A819B1310F8378641DCEF141E3592701D3D80CB35FDC16FB12
```

### Setup Software TPM

If you want to test locally with a [software TPM](https://github.com/stefanberger/swtpm)

- Start `TPM-B`

```bash
## TPM B
rm -rf /tmp/myvtpm2 && mkdir /tmp/myvtpm2
/usr/share/swtpm/swtpm-create-user-config-files
swtpm_setup --tpmstate /tmp/myvtpm2 --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2

## in new window
export TPM2TOOLS_TCTI="swtpm:port=2341"

$ tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l
$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

## export the ekPub
### derive the RSA EK 
tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub 

tpm2_readpublic -c /tmp/ek.ctx -o /tmp/ek.pem -f PEM -n ek.name -Q

tpm2_getekcertificate -X -o EKCert.bin
openssl x509 -in EKCert.bin -inform DER -noout -text
```

To run all the examples:

```bash
export TPMB="127.0.0.1:2341"
export TPM2TOOLS_TCTI="swtpm:port=2341"

### TPM-B make sure the pcr value is 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
### tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
tpm2_pcrread sha256:23

### RSA
go run cmd/main.go --mode publickey --parentKeyType=rsa_ek -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB

# openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out /tmp/key_rsa.pem
go run cmd/main.go --mode duplicate  --secret=/tmp/key_rsa.pem --keyType=rsa \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

go run cmd/main.go --mode import --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey.pem --tpm-path=$TPMB

cd example/
go run rsa/password/main.go --pemFile=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB
cd ..

### pcr
go run cmd/main.go --mode duplicate --keyType=rsa    --secret=/tmp/key_rsa.pem \
     --pcrValues=23:f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b  \
      -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

go run cmd/main.go --mode import --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey.pem --tpm-path=$TPMB

cd example/
go run rsa/pcr/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB

go run rsa/signer_pcr/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB
cd ..

### ECC
# openssl genpkey -algorithm ec -pkeyopt  ec_paramgen_curve:P-256  -out /tmp/key_ecc.pem
go run cmd/main.go --mode duplicate --keyType=ecc --secret=/tmp/key_ecc.pem \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

go run cmd/main.go --mode import --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey.pem --tpm-path=$TPMB

cd example/
go run ecc/password/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB --password=bar
cd ..

### AES
# echo -n "46be0927a4f86577f17ce6d10bc6aa61" > /tmp/aes.key
go run cmd/main.go --mode duplicate --keyType=aes --secret=/tmp/aes.key  \
  --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

go run cmd/main.go --mode import --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB

cd example/
go run aes/password/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB --password=bar
cd ..

### HMAC
# echo -n "change this password to a secret" > /tmp/hmac.key
go run cmd/main.go --mode duplicate --keyType=hmac --secret=/tmp/hmac.key \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json

go run cmd/main.go --mode import  --parentKeyType=rsa_ek --in=/tmp/out.json --out=/tmp/tpmkey.pem   --tpm-path=$TPMB

cd example/
go run hmac/password/main.go --pemFile=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB
cd ..
```

---

### tpmcopy using tpm2_tools

If you want to see how this flow works with pure `tpm2_tools`, see  [PolicyDuplicateSelect and PolicyAuthValue bound PolicyDuplicate](https://gist.github.com/salrashid123/e487848bd5d3538a68c2284e1b24d89d)

Specifically, the following will transfer an rsa key from one TPM to another.  We're using two tpms although `tpmcopy` does not require a a TPM at the source.  We're doing that because tpm2_tools does not allow for an easy way to synthetically duplicate without an actual local TPM.

start two TPMs

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert

rm -rf /tmp/myvtpm2 && mkdir /tmp/myvtpm2
swtpm_setup --tpmstate /tmp/myvtpm2 --tpm2 --create-ek-cert

swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2
swtpm socket --tpmstate dir=/tmp/myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2
```

To transfer from `TPM-A` to `TPM-B`

1) `TPM-B`

Create an endorsement public key and extract the ECC PEM public key:

```bash
export TPM2TOOLS_TCTI="swtpm:port=2341"

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_createek -c ek.ctx -G ecc -u ek.pub 
tpm2_readpublic -c ek.ctx -o ek.pem -f PEM -n ek.name
tpm2_print -t TPM2B_PUBLIC ek.pub
```

copy `ek.pem` to `TPM-A`

2) `TPM-A`

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"
## generate an rsa key
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out /tmp/key_rsa.pem

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

# create any primary
tpm2_createprimary -C o -g sha256 -G rsa -c primaryA.ctx

## create a policy_or(policyAuthValue|policyDuplicateSelect)
tpm2_startauthsession -S sessionA.dat
tpm2_policyauthvalue -S sessionA.dat -L policyA_auth.dat 
tpm2_flushcontext sessionA.dat
rm sessionA.dat

tpm2_loadexternal -C o -g sha256 -G ecc:null:aes128cfb  -u ek.pem -c newparent.ctx \
   --policy=837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa \
    --attributes="fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|restricted|decrypt"
tpm2_readpublic -c newparent.ctx -o new_parent.pub -n new_parent.name

tpm2_startauthsession -S sessionA.dat
tpm2_policyduplicationselect -S sessionA.dat  -N new_parent.name -L policyA_dupselect.dat 
tpm2_flushcontext sessionA.dat
rm sessionA.dat

tpm2_startauthsession -S sessionA.ctx
tpm2_policyor -S sessionA.ctx -L policyA_or.dat sha256:policyA_auth.dat,policyA_dupselect.dat 
tpm2_flushcontext sessionA.ctx
tpm2_flushcontext -t

### now import the external rsa key
tpm2_import -C primaryA.ctx -G rsa2048:rsassa:null  -i /tmp/key_rsa.pem -u key.pub -r key.prv  -p bar -a "sign" -L policyA_or.dat

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primaryA.ctx -r key.prv -u key.pub -c key.ctx -n key.name
tpm2_readpublic -c key.ctx -o dup.pub

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

### create a binding policy
tpm2_startauthsession -S sessionA.dat --policy-session
tpm2_policyduplicationselect -S sessionA.dat  -N new_parent.name  -n key.name -L policyA_dupselect.dat 
tpm2_policyor -S sessionA.dat -L policyA_or.dat sha256:policyA_auth.dat,policyA_dupselect.dat 

## now duplicate
tpm2_flushcontext -t
tpm2_duplicate -C newparent.ctx -c key.ctx -G null  -p "session:sessionA.dat" -r dup.dpriv -s dup.seed
tpm2_flushcontext -t
```

3)  `TPM-B`

on TPM B, import the duplicated keys, seed:

```bash
export TPM2TOOLS_TCTI="swtpm:port=2341"

tpm2 flushcontext -t
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement

tpm2_import -C ek.ctx -u dup.pub -i dup.dpriv -r dup.prv -s dup.seed  --parent-auth session:session.ctx
tpm2_flushcontext -t
tpm2_flushcontext session.ctx
tpm2_flushcontext -t

tpm2 flushcontext -t
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement 
tpm2_load -C ek.ctx -u dup.pub -r dup.prv -c dup.ctx  --auth session:session.ctx
tpm2_readpublic -c dup.ctx -o dup.pub
tpm2_flushcontext session.ctx
tpm2_flushcontext -t


### now create a real policy which will full the conditions set earlier
tpm2_startauthsession -S sessionB.dat  --policy-session
tpm2_policyauthvalue -S sessionB.dat  -L policyB_auth.dat 
tpm2_flushcontext sessionB.dat
rm sessionB.dat

tpm2_startauthsession -S sessionB.dat --policy-session
tpm2_policyduplicationselect -S sessionB.dat  -N new_parent.name -L policyB_dupselect.dat 
tpm2_flushcontext sessionB.dat
rm sessionB.dat

tpm2_startauthsession -S sessionB.dat --policy-session
tpm2_policyauthvalue -S sessionB.dat  -L policyB_auth.dat 
tpm2_policyor -S sessionB.dat -L policyB_or.dat sha256:policyB_auth.dat,policyB_dupselect.dat 

echo "meet me at.." >file.txt
openssl dgst -sha256  -keyform PEM - -sign /tmp/key_rsa.pem -out sig.dat file.txt

tpm2_flushcontext -t
tpm2_sign -c dup.ctx -g sha256  -f plain  -p"session:sessionB.dat+bar" -o sig.rss  file.txt
tpm2_flushcontext -t
```

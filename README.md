## tpmcopy:  Securely transfer an RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)

Utility function you can use to securely copy an `RSA` or `ECC` or `AES` or `HMAC`  **KEY** from your laptop to a remote `Trusted Platform MOdule (TPM)`

Basically, you can transfer a key from `TPM-A` to `TPM-B` such that the key cannot get decrypted or exposed outside of `TPM-B`.  

The key you transfer will not get exposed into user space but can be used to sign/encrypt/decrypt/hmac while always existing _inside_ the destination `TPM`.

Furthermore, you can place TPM based conditions on the transfer and the use of that key on the destination TPM

For examples, you can specify a passphrase or certain `PCR` values must be present on use for the destination key.

Alternativley, if you just want some secret to get transferred securely only to get decrypted in  userspace (eg securely transfer raw data as opposed to a TPM-embedded key), see 

* [Go-TPM-Wrapping - Go library and CLI utiity for encrypting data using Trusted Platform Module (TPM)](https://github.com/salrashid123/go-tpm-wrapping)

---

### Overview

At a high level, this utility basically performs [tpm2_duplicate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md) and involves several steps:

If you want to transfer an external `RSA|ECC|AES|HMAC` key _from_  `TPM-A`  to `TPM-B`, you will need to

1. On `TPM-B`, extract the [Endorsement Public Key](https://trustedcomputinggroup.org/wp-content/uploads/EK-Credential-Profile-For-TPM-Family-2.0-Level-0-V2.5-R1.0_28March2022.pdf)
   Copy the public key to the system that has `TPM-A`

2. On `TPM-A`,  [import](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_import.1.md) the external `RSA|ECC|AES|HMAC`

3. On `TPM-A` use `TPM-B's` public key to [duplicate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md) the loaded key such that it can only get loaded -inside- `TPM-A`
   The duplicate step will encrypt the external key such that only `TPM-B` can import it.
   The encrypted key is saved as a file which you will need to copy to `TPM-B`

4. On `TPM-B`  [import](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_import.1.md) the duplicated key you  copied from `TPM-A`
   The imported key is saved in TPM encoded PEM format for later use

5. On `TPM-B` use the imported key to sign,encrypt,decrypt,hmac

Note that step 3 is constructed with `PolicyDuplicateSelect` which ensures the key can only exist on the target TPM and cannot get exported further.  For more information, see [Transfer TPM based key using PCR policy](https://gist.github.com/salrashid123/a61e09684c5d59440834d91241627458)

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
| **`-ownerpw`** | passphrase for the TPM owner (default: "") |
| **`-keyName`** | description of the key to annotate (default: "") |
| **`-pcrValues`** | comma separated list of current pcr values to bind the key to (default: "") |
| **`-tpmPublicKeyFile`** | File to write the public key to  (default: ` /tmp/public.pem`) |
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
go build -o tpm2copy cmd/main.go
```

## Usage


### RSA

To tranfer an `RSA` key from `TPM-A` to `TPM-B`

##### Password Policy

If you want to bind the key to a passphrase

1) on `TPM-A`

Generate an RSA key 

```bash
### for RSA-SSA (default)
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out /tmp/key_rsa.pem
```

2) on `TPM-B`

Extract `Endorsement Public Key`

```bash
export TPMB="/dev/tpmrm0"

tpm2copy  --mode publickey --keyType=rsa -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB
```

Alternatively, you can use `tpm2_tools`:

```bash
tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub
tpm2_readpublic -c /tmp/ek.ctx -o /tmp/public.pem -f PEM -n /tmp/ek.name 

## or extract the ekcert x509 
tpm2_getekcertificate -X -o EKCert.bin
openssl x509 -in EKCert.bin -inform DER -noout -text
```

copy `public.pem` to `TPM-A`

3) on `TPM-A`

load and duplicate the external key and bind it to a password

```bash
### you can use a  TPM simulator or a real tpm to load the external key
export TPMA="/dev/tpmrm0"

tpm2copy --mode duplicate  --secret=/tmp/key_rsa.pem  --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA
```

copy `/tmp/out.json` to `TPM-B`

4) on `TPM-B`

import the key

```bash
tpm2copy --mode import --password=bar --in=/tmp/out.json --out=/tmp/tpmkey.pem  --tpm-path=$TPMB
```

5) Use key

```bash
cd example/
go run rsa/password/main.go --pemFile=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB
```

##### PCR Policy

If you wanted to use a PCR policy like one that enforces that to use the key `TPM-B` must have `pcr 23=f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b`


1) `TPM-A`

Create the ekPub and ensure the PCR value is set

```bash

### first make sure the target TPM has the correct PCR to bind against
export TPMA="/dev/tpmrm0"
tpm2copy --mode publickey -tpmPublicKeyFile /tmp/public.pem --tpm-path=$TPMB

$ tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l

$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

copy `public.pem` to `TPM-A`

2) `TPM-B`

```bash
### you can use a  TPM simulator or a real tpm to load the external key
export TPMA="/dev/tpmrm0"
tpm2copy --mode duplicate --keyType=rsa \
   --secret=/tmp/key_rsa.pem  --pcrValues=23:f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b \
   -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA
```

copy `/tmp/out.json` to `TPM-B`

3) `TPM-B`

```bash
tpm2copy --mode import --in=/tmp/out.json --out=/tmp/tpmkey.pem --tpm-path=$TPMB
```

4) Test signature

```bash
cd example
### sign directly
go run rsa/pcr/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB
### using crypto.Signer
go run rsa/signer_pcr/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB
```

### ECC

To transfer an `ECC-P256` key

```bash
### TPM-A
openssl genpkey -algorithm ec -pkeyopt  ec_paramgen_curve:P-256  -out /tmp/key_ecc.pem

### TPM-B
export TPMB="/dev/tpmrm0"
tpm2copy --mode publickey -tpmPublicKeyFile /tmp/public.pem --tpm-path=$TPMB
###  copy  to TPM-A

### TPM-A
## Password
export TPMA="/dev/tpmrm0"
tpm2copy --mode duplicate --keyType=ecc --secret=/tmp/key_ecc.pem \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA

###  copy /tmp/out.json to TPM-B

### TPM-B
tpm2copy --mode import --in=/tmp/out.json --out=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB

### test
go run ecc/password/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB --password=bar
```

### AES

To transfer `AES-128 CFB`

```bash
### TPM-A
export secret="46be0927a4f86577f17ce6d10bc6aa61"
echo -n $secret > /tmp/aes.key

### TPM-B
export TPMB="/dev/tpmrm0"
tpm2copy --mode publickey -tpmPublicKeyFile /tmp/public.pem --tpm-path=$TPMB
###  copy  to TPM-A

### TPM-A
export TPMA="/dev/tpmrm0"
tpm2copy --mode duplicate --keyType=aes --secret=/tmp/aes.key \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA

###  copy /tmp/out.json to TPM-B

### TPM-B
tpm2copy --mode import --in=/tmp/out.json --out=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB

### test
go run aes/password/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB --password=bar
```


### HMAC

To transfer an `HMAC 256` key,

```bash
### TPM-A
export secret="change this password to a secret"
echo -n $secret > /tmp/hmac.key
hexkey=$(xxd -p -c 256 < /tmp/hmac.key)
echo $hexkey

### TPM-B
export TPMB="/dev/tpmrm0"
tpm2copy --mode publickey -tpmPublicKeyFile /tmp/public.pem --tpm-path=$TPMB
###  copy  to TPM-A

### TPM-A
export TPMA="/dev/tpmrm0"
tpm2copy --mode duplicate --keyType=hmac --secret=/tmp/hmac.key \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA

###  copy /tmp/out.json to TPM-B

### TPM-B
tpm2copy --mode import --in=/tmp/out.json --out=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB

### test
go run hmac/password/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB --password=bar
```

---

### TPM2_TOOLS compatibility

If you wanted to use `tpm2_tools` on the key imported to `TPM-B`, then use the `--pubout=` and `--privout=` parameters when importing.

What that'll do is save the key as `[TPM2B_PUBLIC, TPM2B_PRIVATE]`

For example, the follwoing will import the password or pcr policy encoded files and use tpm2_tools to perform further operations.

on `TPM-B`, save the ek (and optionallhy as a persistent handle)

```bash

tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub
tpm2_readpublic -c /tmp/ek.ctx -o /tmp/ek.pem -f PEM -n /tmp/ek.name
```

then when running `import`, specify the files

```bash
go run cmd/main.go --mode import \
   --pubout=/tmp/pub.dat --privout=/tmp/priv.dat --in=/tmp/out.json \
   --out=/tmp/tpmkey.pem --tpm-path=$TPMB
```

If the key had a `password` policy

```bash
tpm2 flushcontext -t
tpm2 startauthsession --session /tmp/session.ctx --policy-session
tpm2 policysecret --session /tmp/session.ctx --object-context endorsement

tpm2_load -C /tmp/ek.ctx -c /tmp/key.ctx -u /tmp/pub.dat -r /tmp/priv.dat --auth session:session.ctx

tpm2 flushcontext -t
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement

echo -n "foo" >/tmp/file.txt
tpm2_sign -c key.ctx -g sha256  -f plain -p bar -o sig.rss  /tmp/file.txt
```

If the key had a pcr policy

```bash
### load
tpm2 flushcontext -t
tpm2 startauthsession --session /tmp/session.ctx --policy-session
tpm2 policysecret --session /tmp/session.ctx --object-context endorsement
tpm2_load -C /tmp/ek.ctx -c /tmp/key.ctx -u /tmp/pub.dat -r /tmp/priv.dat --auth session:session.ctx

## regenerate the full policy
tpm2_startauthsession -S sessionA.dat --policy-session
tpm2_policyduplicationselect -S sessionA.dat  -N /tmp/ek.name -L policyA_dupselect.dat 
tpm2_flushcontext sessionA.dat
rm sessionA.dat

tpm2_startauthsession -S sessionA.dat --policy-session
tpm2_policypcr -S sessionA.dat -l "sha256:23" -f pcr23_valA.bin -L policyA_pcr.dat 
tpm2_policyor -S sessionA.dat -L policyA_or.dat sha256:policyA_pcr.dat,policyA_dupselect.dat 

### test sign
echo -n "foo" >/tmp/file.txt
tpm2_sign -c key.ctx -g sha256 -f plain  -o signB.raw /tmp/file.txt -p "session:sessionA.dat" 
rm sessionA.dat
```

### Setup Software TPM

If you want to test locally with two [software TPM](https://github.com/stefanberger/swtpm)

- Start `TPM-A`

```bash
## TPM A
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
/usr/share/swtpm/swtpm-create-user-config-files
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

## in new window
export TPM2TOOLS_TCTI="swtpm:port=2321"
```

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
$ tpm2_pcrextend 23:sha256=0x0$000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

## export the ekPub
### derive the RSA EK and persist it to nv at handle 0x81010001
tpm2_evictcontrol -c 0x81010001
tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub -c 0x81010001
tpm2_readpublic -c /tmp/ek.ctx -o /tmp/ek.pem -f PEM -n ek.name -Q

tpm2_getekcertificate -X -o EKCert.bin
openssl x509 -in EKCert.bin -inform DER -noout -text
```

### Session Encryption

Each operation uses [encrypted sessions](https://trustedcomputinggroup.org/wp-content/uploads/TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation_8May23-3.pdf) by default and interrogates the TPM for the current EK directly.

If for whatever reason you want to specify the "name" of the EK to to use, set the `--tpm-session-encrypt-with-name=` parameter shown below

```bash
# for tpmA
tpm2_createek -c /tmp/primaryA.ctx -G rsa  -Q
tpm2_readpublic -c /tmp/primaryA.ctx -o /tmp/ekpubA.pem -n /tmp/ekpubAname.bin -f PEM -Q
xxd -p -c 100 /tmp/ekpubAname.bin 
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
  bool userAuth = 4;  
  repeated PCRS pcrs = 5;  
  Key key = 6;
  repeated bytes authValue = 7;
}

message PCRS {
  int32 pcr = 1;
  bytes value = 2;
}

message Key {
  string name = 1;
  string parentName = 2;
  bytes dupPub = 3;
  bytes dupDup = 4;
  bytes dupSeed = 5;
}
```

So an output file may look like:

```json
{
  "version": 1,
  "type": "RSA",
  "userAuth": true,
  "key": {
    "parentName": "000bbc0c7f8b565f09e4614624fa6f46ece235c9904d47050e8a8dd466ac9b96d49b",
    "dupPub": "AAEACwAEAEAAIFF/bp7yUPnb8+9Yxzd7t+G1XfxzlxHT5pLU2tX9FBQzABAAFAALCAAAAQABAQDYVPdGjOF0sqBDif2WhImCDy8MJhRDaGmmsqb4ZA1F7ipuwgTK+16rcILmpFXhLJHWLAPUY6IQAE8cBZtchdlV/DJXw0QdFHI2BZpG585/dHg/YtPeHhb6YL6zTsnORwKVMICio7I+IUyzziMXLI7gbzH/3U+fUWw/7UFl4V48xwcrG42vmhNdA3+trnpT95x0A81DBHwDX2yd55RuIUZMcOzB+TT7t71kPkX0mDn6t9OKSYdEBWZQqCsYjnVIHH5ALzEVJIdZaH1mlAMes3mK/b3CvOzo1GNpPbqk6JyKJmxK5z0IfKYPw1Qe3K6SBQjqS9t88TYsDsaGsjfzCQgV",
    "dupDup": "ACBfLKyJByo0CeEfy7le/9BIduaQ0XSIS9F3O4474ZP3dvGMzH2bs2BPvxm04j4M+vaCO9JizcHuSkDvPsYLCbVzlJydw5OWIElYaC7Cjy+/CqWdDIhU9L0KvTqxt/vEToT9YmWxekhiBvZS3ldIVop0LKv20qg9JuiHosqdJVCQcW0LWVwKmDV34SaKdkww4uSuVp3Cfe24+oiwNHM8Vx5ZpIi1RgKMzDlNzh6aOlE1yxJKK87ZITZXf1Hs2YlyUIMXKJTD1HPrI+Tr",
    "dupSeed": "I6KssTdPlLpPV1COj89/rRH5UvaivSsOWLY/kiV1d7dTqcH1bb7zndTh6NAkLVoANnhaLYoV87ypBFoNbcZOBlj7K2HwEFpyHBOpIhk6Tn1FzfqcY9FxKoTfeHyMB6VPtoVw+5YsF+p6QOIfVxE0XtfL4AMWNwQmKgavaPDdRPpD4Etnk16lH27GS/4nL/Dwcpbzwnu/117DbZbW29KDrsMFPmCPeKStvOJv102AP7Kmo3vS2DZP25hM3MN/8Q26jVMJdeP66AlBzVDuzhfVqntuRE9eTTLMTMHTZaO5+U2HOkXwQ/g2MuzodjPODQEw4uzuCeCPA/UHKDMYKjjYHA=="
  }
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

#### TODO:

Populate the `keyfile.TPMKey.AuthPolicy  []*TPMAuthPolicy[]` parameter with the encoded policies:

* [Reconstruct Policy using command parameters](https://github.com/salrashid123/tpm2/tree/master/policy_gen)

---

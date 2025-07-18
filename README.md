## tpmcopy:  Securely transfer an RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)

Utility function you can use to securely copy an `RSA` or `ECC` or `AES` or `HMAC`  **KEY** from your laptop to a remote `Trusted Platform MOdule (TPM)`

Basically, you can transfer a key from `TPM-A` to `TPM-B` such that the key cannot get decrypted or exposed outside of `TPM-B`.  

The key you transfer will not get exposed into user space but can be used to sign/encrypt/decrypt/hmac while always existing _inside_ the destination `TPM`.

Furthermore, you can place TPM based conditions on the transfer and the use of that key on the destination TPM

For examples, you can specify a passphrase or certain `PCR` values must be present on use for the destination key.

Alternativley, if you just want some secret to get transferred securely only to get decrypted in  userspace (eg securely transfer raw data vs a key),see 

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

---

| Option | Description |
|:------------|-------------|
| **`-tpm-path`** | Path to the TPM device (default: `/dev/tpmrm0`) |
| **`-mode`** | Operation mode: `publickey duplicate import` (default: ``) |
| **`-keyType`** | type of key to import/export (`rsa ecc aes hmac`) (default: "rsa") |
| **`-out`** | File to write the file to import (default: `"/tmp/out.json"`) |
| **`-in`** | File to read the file to import (default: `"/tmp/out.json"`) |
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

---

## Build

You can use the binary in the `Releases` page as a standalone cli or load as a library or just build: 

```bash
go build -o tpm2copy cmd/main.go
```

## Usage


### RSA

To tranfer an `RSA` key from `TPM-A` to `TPM-B`

##### PasswordPolicy

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

go run cmd/main.go --mode publickey -tpmPublicKeyFile /tmp/public.pem --tpm-path=$TPMB
```

Alternatively, you can use `tpm2_tools`:

```bash
tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub
tpm2_readpublic -c /tmp/ek.ctx -o /tmp/public.pem -f PEM -Q

## or extract the ekcert x509 
tpm2_getekcertificate -X -o EKCert.bin
openssl x509 -in EKCert.bin -inform DER -noout -text
```

copy `public.pem` to `TPM-A`

3) on `TPM-A`

load and duplicate the external key and bind it to a password

```bash
### you can use a  TPM simulator or a real tpm to load the external key
export TPMA="simulator" ### or export TPMA="/dev/tpmrm0"

go run cmd/main.go --mode duplicate  --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA
```

copy `/tmp/out.json` to `TPM-B`

4) on `TPM-B`

import the key
```bash
go run cmd/main.go --mode import --password=bar --in=/tmp/out.json --out=/tmp/tpmkey.pem  --tpm-path=$TPMB
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
go run cmd/main.go --mode publickey -tpmPublicKeyFile /tmp/public.pem --tpm-path=$TPMB

$ tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l

$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrextend 23:sha256=0x0$000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

copy `public.pem` to `TPM-A`

2) `TPM-B`

```bash
### you can use a  TPM simulator or a real tpm to load the external key
export TPMA="simulator" ### or export TPMA="/dev/tpmrm0"
go run cmd/main.go --mode duplicate --keyType=rsa \
   --secret=/tmp/key_rsa.pem  --pcrValues=23:f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b \
   -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA
```

copy `/tmp/out.json` to `TPM-B`

3) `TPM-B`

```bash
go run cmd/main.go --mode import --in=/tmp/out.json --out=/tmp/tpmkey.pem --tpm-path=$TPMB

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
go run cmd/main.go --mode publickey -tpmPublicKeyFile /tmp/public.pem --tpm-path=$TPMB
###  copy  to TPM-A

### TPM-A
## Password
export TPMA="simulator" ### or export TPMA="/dev/tpmrm0"
go run cmd/main.go --mode duplicate --keyType=ecc --secret=/tmp/key_ecc.pem \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA

###  copy /tmp/out.json to TPM-B

### TPM-B
go run cmd/main.go --mode import --in=/tmp/out.json --out=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB

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
go run cmd/main.go --mode publickey -tpmPublicKeyFile /tmp/public.pem --tpm-path=$TPMB
###  copy  to TPM-A

### TPM-A
export TPMA="simulator" ### or export TPMA="/dev/tpmrm0"
go run cmd/main.go --mode duplicate --keyType=aes --secret=/tmp/aes.key \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA

###  copy /tmp/out.json to TPM-B

### TPM-B
go run cmd/main.go --mode import --in=/tmp/out.json --out=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB

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
go run cmd/main.go --mode publickey -tpmPublicKeyFile /tmp/public.pem --tpm-path=$TPMB
###  copy  to TPM-A

### TPM-A
export TPMA="simulator" ### or export TPMA="/dev/tpmrm0"
go run cmd/main.go --mode duplicate --keyType=hmac --secret=/tmp/hmac.key \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA

###  copy /tmp/out.json to TPM-B

### TPM-B
go run cmd/main.go --mode import --in=/tmp/out.json --out=/tmp/tpmkey.pem  --password=bar --tpm-path=$TPMB

### test
go run hmac/password/main.go --pemFile=/tmp/tpmkey.pem --tpm-path=$TPMB --password=bar
```

---

### Setup Software TPM

If you want to test locally with two [software TPM]s(https://github.com/stefanberger/swtpm)

Start `TPM-A`

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
tpm2_readpublic -c /tmp/ek.ctx -o /tmp/ek.pem -f PEM -Q

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

This utility encodes the key to transfer as protobuf

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
  bytes ekPub = 2;
  bytes dupPub = 3;
  bytes dupDup = 4;
  bytes dupSeed = 5;
}
```

So an output file may look like:

```json
cat /tmp/out.json| jq '.'

{
  "version": 1,
  "type": "AES",
  "pcrs": [
    {
      "pcr": 23,
      "value": "9aX9QtFqIDAnmO9u0wmXm0MAPSMg2fDo6pgxqSdZ+0s="
    }
  ],
  "key": {
    "ekPub": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFpT21mVFVhaGZPODhPNjArajhqZgo0VnQvQ3Rpd1BsMmQyWE5oUno2NE5LWDZreFExVzg3NnAwbFFsbFM1a25UZ1pkdG1xRzBzL0ZqN2hRM1pRSXJuCkpsUkRoZC9vai8yNFk3RzV4RUhTNkJML1VQTzhPUS9VaHgxMjZOb3Npb0FhcmJ0d2R5T1lxSDBWQkwyMjJ4UXUKMHpCd0o1cVcxMjAwN2c1Z2dzLzJjeklNbUxXSjZWN1p1Vy9lV1JwQTd4eWFOYS9KZUw3U1NQMEM4b0RrbkxPYwpjZlI1ZGpYd0J1bVZpbXJLUjZxb1h0bzFzbE1CZjYxT3pQNnFVT2VrTnJSSXh6QXZ4ZmZ6SXlER0hzanM5SXZSCmhib29MSlJ1czFFRklzeTdTdFF5dENXY1lOemhicHI3cGFMNXI2MnFkOGZ5VVFjQ0IwWFIwbzJuVy9VRStzRVoKRndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
    "dupPub": "AAEACwAEAAAAIBpYx5LkU8MQ4Phrbixlk+FiA8bTuGi1PgMO8xJhA351ABAAFAALCAAAAQABAQDYVPdGjOF0sqBDif2WhImCDy8MJhRDaGmmsqb4ZA1F7ipuwgTK+16rcILmpFXhLJHWLAPUY6IQAE8cBZtchdlV/DJXw0QdFHI2BZpG585/dHg/YtPeHhb6YL6zTsnORwKVMICio7I+IUyzziMXLI7gbzH/3U+fUWw/7UFl4V48xwcrG42vmhNdA3+trnpT95x0A81DBHwDX2yd55RuIUZMcOzB+TT7t71kPkX0mDn6t9OKSYdEBWZQqCsYjnVIHH5ALzEVJIdZaH1mlAMes3mK/b3CvOzo1GNpPbqk6JyKJmxK5z0IfKYPw1Qe3K6SBQjqS9t88TYsDsaGsjfzCQgV",
    "dupDup": "ACDrGDROfkDRq8ckoIrCDBOh+NpMstw8qWZvSYMfp3NQNaoRY3iRkwhKedu6WXLmsTTC0iLRA7/wT8NQeUVdvXYVr8ICI+ET3iGH3AMmGjRWh7gS8Uytvi8rC8yE9Z7SWICwyFas5Vy92ZGQ01+9QvyRoPFAkOrOe6C1d6dNywE4MJL3fCGIVPG1AySa4nWWKKJk7BfVQ86qqqSbJu+veWAYMPZA6x0gNw2hEjW/9XhuQDVG9rXseFUC5tyh2cjSRbt28DqWzF3eu+qJ",
    "dupSeed": "SSABqRX/aHB5N0PaljRkWXZqoJkSwIDmDFi83tI61A95oAWEnuT2JJ0vjK/+UYWGwu1UYZWMgeVY/EmuBen72kmPbu2jxKaw4jafHgN3VILsF0drEMyjrXehFiArJP76llB8OZwG9onGFIAgfBzQMtjolAdjNaU8+UUKc2tg/tvQb2d5ueaRUxX4Gdpu9QgTnf0UyabM4QHKW74mfkpBbNxSZw6Lcv61UuYSkgCidNgmP+MpWMdbf+nHepE6AtW5cQN2UKA/1G0uMRpuj2+6zICq6EwNW2fnVdtXj/hmhEY/Xn6+p/5x3oSWv8d+dHW50CEIzxlozFw32KL4xA+tAQ=="
  }
}
```

Finally, the `Import()` function saves the imported using [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html) which is the format openssl (mostly) follows.


One specific difference to note is the parent value encoded in the PEM file is transient.  If you want to specify a persistent handle for the PEM file which indicates its an  EK

on `TPM-B`, save the ek as a peristent handle

```bash
tpm2_evictcontrol -c 0x81010001
tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub -c 0x81010001
Tpm2_readpublic -c /tmp/ek.ctx -o /tmp/ek.pem -f PEM -Q
```

then when running `impoart`, specify the handle

```bash
go run cmd/main.go --mode import --in=/tmp/out.json --out=/tmp/tpmkey.pem --parent 0x81010001 --tpm-path=$TPMB


$ cat /tmp/tpmkey.pem 
-----BEGIN TSS2 PRIVATE KEY-----
MIICMAYGZ4EFCgEDAgUAgQEAAQSCAToBOAABAAsABABAACBRf26e8lD52/PvWMc3
e7fhtV38c5cR0+aS1NrV/RQUMwAQABQACwgAAAEAAQEA2FT3RozhdLKgQ4n9loSJ
gg8vDCYUQ2hpprKm+GQNRe4qbsIEyvteq3CC5qRV4SyR1iwD1GOiEABPHAWbXIXZ
VfwyV8NEHRRyNgWaRufOf3R4P2LT3h4W+mC+s07JzkcClTCAoqOyPiFMs84jFyyO
4G8x/91Pn1FsP+1BZeFePMcHKxuNr5oTXQN/ra56U/ecdAPNQwR8A19sneeUbiFG
THDswfk0+7e9ZD5F9Jg5+rfTikmHRAVmUKgrGI51SBx+QC8xFSSHWWh9ZpQDHrN5
iv29wrzs6NRjaT26pOiciiZsSuc9CHymD8NUHtyukgUI6kvbfPE2LA7GhrI38wkI
FQSB4ADeACC8Xk6lqtcdXW6xFmQ4a/Bh8teZl+QwIHbidVhXtvF9ewAQKj/asaTM
JSohdcQjBitC8sroagYNjYUzzDcY9b0ik29NIm2Ve7o/UmDS1oKZz9UD5wFiuh/R
XAxtOBNwN9BJyj/gXGQ823QZdCGbv+ZoaC96kwEM518sjJw0GcYzFEkJaFkEcBM9
wt1JJgS7zO2UG/ZtNxJxNpqFu6P7yvgo0GvcQFsuUujgdavBGJNuNjtLVYp7nNaX
ICPvLqJ5+Fi3nqz0xtO7wdt4zjnxPPTJRg6h/OSltIXQltX2
-----END TSS2 PRIVATE KEY-----


### which will encode the persistent handle as the parent object 

$  openssl asn1parse -in tpmkey.pem
    0:d=0  hl=4 l= 560 cons: SEQUENCE          
    4:d=1  hl=2 l=   6 prim: OBJECT            :2.23.133.10.1.3
   12:d=1  hl=2 l=   5 prim: INTEGER           :81010001   <<<<<<<<<<<<<<<<<<<<<<<
   19:d=1  hl=4 l= 314 prim: OCTET STRING      [HEX DUMP]:01380001000B000400400020517F6E9EF250F9DBF3EF58C7377BB7E1B55DFC739711D3E692D4DAD5FD14143300100014000B0800000100010100D854F7468CE174B2A04389FD968489820F2F0C2614436869A6B2A6F8640D45EE2A6EC204CAFB5EAB7082E6A455E12C91D62C03D463A210004F1C059B5C85D955FC3257C3441D147236059A46E7CE7F74783F62D3DE1E16FA60BEB34EC9CE4702953080A2A3B23E214CB3CE23172C8EE06F31FFDD4F9F516C3FED4165E15E3CC7072B1B8DAF9A135D037FADAE7A53F79C7403CD43047C035F6C9DE7946E21464C70ECC1F934FBB7BD643E45F49839FAB7D38A498744056650A82B188E75481C7E402F3115248759687D6694031EB3798AFDBDC2BCECE8D463693DBAA4E89C8A266C4AE73D087CA60FC3541EDCAE920508EA4BDB7CF1362C0EC686B237F3090815
  337:d=1  hl=3 l= 224 prim: OCTET STRING      [HEX DUMP]:00DE0020BC5E4EA5AAD71D5D6EB11664386BF061F2D79997E4302076E2755857B6F17D7B00102A3FDAB1A4CC252A2175C423062B42F2CAE86A060D8D8533CC3718F5BD22936F4D226D957BBA3F5260D2D68299CFD503E70162BA1FD15C0C6D38137037D049CA3FE05C643CDB741974219BBFE668682F7A93010CE75F2C8C9C3419C63314490968590470133DC2DD492604BBCCED941BF66D371271369A85BBA3FBCAF828D06BDC405B2E52E8E075ABC118936E363B4B558A7B9CD6972023EF2EA279F858B79EACF4C6D3BBC1DB78CE39F13CF4C9460EA1FCE4A5B485D096D5F6

```

---


#### TODO:

Populate the `keyfile.TPMKey.AuthPolicy  []*TPMAuthPolicy[]` parameter with the encoded policies:

* [Reconstruct Policy using command parameters](https://github.com/salrashid123/tpm2/tree/master/policy_gen)

---

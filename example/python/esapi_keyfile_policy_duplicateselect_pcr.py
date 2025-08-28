from tpm2_pytss import *
from tpm2_pytss.internal.templates import ek_rsa2048
# from tpm2_pytss.internal.templates import _ek

from tpm2_pytss.tsskey import TSSPrivKey

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from tpm2_pytss.encoding import (
    base_encdec,
    json_encdec,
)

ectx = ESAPI(tcti="swtpm:port=2341")
ectx.startup(TPM2_SU.CLEAR)


def setup_ek_session(ectx, ek_handle):
    sym = TPMT_SYM_DEF(
        algorithm=TPM2_ALG.XOR,
        keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
        mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
    )
    
    session = ectx.start_auth_session(
        tpm_key=ek_handle,
        bind=ESYS_TR.NONE,
        session_type=TPM2_SE.POLICY,
        symmetric=sym,
        auth_hash=TPM2_ALG.SHA256,
    )

    nonce = ectx.trsess_get_nonce_tpm(session)

    expiration = -(10 * 365 * 24 * 60 * 60)

    ectx.policy_secret(
        ESYS_TR.ENDORSEMENT, session, nonce, b"", b"", expiration
    )
    ectx.trsess_set_attributes(session, TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
    return session

tmpl = ek_rsa2048.template
# nv, tmpl = _ek.EK_RSA2048

inSensitive = TPM2B_SENSITIVE_CREATE()
ek_handle, ek_pub, _, _, _ = ectx.create_primary(
    inSensitive, tmpl, ESYS_TR.ENDORSEMENT)

ek_name = ek_pub.get_name()
print(ek_name)


sess = setup_ek_session(ectx, ek_handle)

f = open("/tmp/tpmkey.pem", "r")
k = TSSPrivKey.from_pem(f.read().encode("utf-8"))

rsaKeyHandle = ectx.load(ek_handle, k.private, k.public, session1=sess)
rsa_name = rsaKeyHandle.get_name(ectx)
# print(aes_name)
## ************************************


v = ek_pub.publicArea
enc = json_encdec()
vc =enc.encode(v)
print(vc)

pol={
    "name": "MyDuplicationPolicy",
    "description":"Policy DuplicateSelect",
    "policy":[
                {
                    "type": "duplicationSelect",
                    "newParentName": "{}".format(ek_name) ,
                    #"newParentPath": "{}".format(key_path),
                    #"newParentPublic": vc
                    #"includeObject": "YES",
                    #"objectName": "{}".format(rsa_name)                    
                }
    ]
}

polstr = json.dumps(pol).encode()

sess = ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=TPMT_SYM_DEF(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(sym=128),
                mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
            ),        
            auth_hash=TPM2_ALG.SHA256,
        )


def dup_cb(path):
    print(path)
    p = ek_pub.publicArea
    return p


try: 
    with policy(polstr, TPM2_ALG.SHA256) as p:
                p.set_callback(policy_cb_types.CALC_PUBLIC, dup_cb)
                p.calculate()
                
                cjb = p.get_calculated_json()
                dig = p.get_calculated_digest()
                #p.execute(ectx, sess)
except Exception as e:
    print(e)
    sys.exit(1)

# json_object = json.loads(cjb)
# print(json.dumps(json_object, indent=4))

# ectx.policy_auth_value(sess)
  
# ectx.trsess_set_attributes(
#     sess, (TPMA_SESSION.DECRYPT | TPMA_SESSION.ENCRYPT )
# )    
   

# dupselect_policy_digest = ectx.policy_get_digest(sess)
# print(dig)
ectx.flush_context(sess)

pcrsels = TPML_PCR_SELECTION.parse("sha256:23")
_, _, digests, = ectx.pcr_read(pcrsels)
print(digests[0].hex())


# # --------------------------------------

pol={
    "name": "MyPolicyOR",
    "description":"Policy OR",
    "policy": [
        {
         "type": "or",
            "branches": [ 
                {
                    "name": "pcrPolicy",
                    "description":"Policy PCR",
                    "policy": [
                        {                       
                            "type":"POLICYPCR",
                            "pcrs":[
                                {
                                    "pcr":23,
                                    "hashAlg":"TPM2_ALG_SHA256",
                                    "digest":"{}".format(digests[0].hex())
                                }
                            ]
                        }
                    ]
                },
                {
                    "name": "duplicationSelect",
                    "description":"Policy DuplicateSelect",
                    "policy": [
                        {
                            "type": "duplicationSelect",
                            "newParentName": "{}".format(ek_name),
                            #"newParentPath": "{}".format("/hs"),
                            #"newParentPublic": vc,
                            #"includeObject": "YES",
                            #"objectName": "{}".format(rsa_name)
                        }
                    ]    
                },                
            ],
        },
    ],
}


polstr = json.dumps(pol).encode()
sess = ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=TPMT_SYM_DEF(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(sym=128),
                mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
            ),   
            auth_hash=TPM2_ALG.SHA256,    
        )
#ectx.tr_set_auth(sess, "bar")

ectx.trsess_set_attributes(
    sess, (TPMA_SESSION.DECRYPT | TPMA_SESSION.ENCRYPT )
)     
      
def polsel_cb(auth_object, branches):
            print(auth_object)
            print(branches)
            return 0 #len(branches) -2

with policy(polstr, TPM2_ALG.SHA256) as p:
            
            p.set_callback(policy_cb_types.EXEC_POLSEL, polsel_cb)
            p.calculate()
            cjb = p.get_calculated_json()
            dig = p.get_calculated_digest()
            print(dig)
            
            p.execute(ectx, sess)

# --------------------------------------
            
json_object = json.loads(cjb)
print(json.dumps(json_object, indent=4))

dig2b = ectx.policy_get_digest(sess)     
print(dig2b)       


scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
scheme.details.any.hashAlg = TPM2_ALG.SHA256
validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)

digest, ticket = ectx.hash(b"fooo", TPM2_ALG.SHA256, ESYS_TR.OWNER)

s = ectx.sign(rsaKeyHandle, TPM2B_DIGEST(digest), scheme, validation, session1=sess)

print("signature")
print(s.signature.rsassa.sig)

ectx.flush_context(ek_handle)
ectx.flush_context(rsaKeyHandle)
ectx.close()
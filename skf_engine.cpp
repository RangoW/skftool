#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/gmskf.h>
#include <openssl/sm2.h>

#include <string.h>
#include <stdint.h>
int my_pkey_meth_init(EVP_PKEY_CTX *ctx) { return 1; }

void my_pkey_meth_cleanup(EVP_PKEY_CTX *ctx) { return; }

int my_pkey_meth_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) { return 1; }

int my_pkey_meth_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  if (type == EVP_PKEY_CTRL_GET_SIGNER_ZID) {
    // 计算 ZID
    unsigned char zid[64];
    size_t zlen = sizeof(zid);
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (!SM2_compute_id_digest(EVP_sm3(), SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH, zid, &zlen, ec_key)) {
        fprintf(stderr, "compute zid failed\n");
        return 0;
    }

    void** p3  = (void**)p2;
    *p3 = (void*)alloca(32 * sizeof(  char));
    memcpy(*p3, zid, zlen);
  }
  return 1;
}

HCONTAINER ghCt;
int my_pkey_meth_sign(EVP_PKEY_CTX *ctx, unsigned char *sigout, size_t *siglen,
                      const unsigned char *tbs, size_t tbslen) {

  ECCSIGNATUREBLOB skfSig;
  ULONG uret = SKF_ECCSignData(ghCt, (BYTE *)tbs, tbslen, &skfSig);
  if (uret != SAR_OK)
    return 0;

  // DER (R+S)
  BIGNUM *r = BN_new();
  BN_bin2bn(skfSig.r+32, 32, r);
  BIGNUM *s = BN_new();
  BN_bin2bn(skfSig.s+32, 32, s);

  LPSTR p = NULL;
  LPSTR sig = NULL;
  int slen = 0;
  ECDSA_SIG* eccSig = ECDSA_SIG_new();
  ECDSA_SIG_set0(eccSig, r, s);

  slen = i2d_ECDSA_SIG(eccSig, NULL);
  sig = (LPSTR)malloc(slen);
  p = sig;
  slen = i2d_ECDSA_SIG(eccSig, &p);

  memcpy(sigout, sig, slen);
  *siglen = slen;
  return 1;
}

int item_sign(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *alg1,
              X509_ALGOR *alg2, ASN1_BIT_STRING *sig) {
  return 1;
}

const unsigned char CHINA_CODE[] = "CN";
int gen_csr(unsigned char *cn, HCONTAINER hct, BYTE *x, BYTE *y, char* csr) {
  ghCt = hct;
  EVP_PKEY *pKey = EVP_PKEY_new();
  EC_KEY *ecPKey = nullptr;
  ecPKey = EC_KEY_new_by_curve_name(NID_sm2p256v1);
  const EC_GROUP *grp = EC_KEY_get0_group(ecPKey);
  EC_POINT *point = EC_POINT_new(grp);
  BIGNUM *bX = BN_bin2bn(x, 32, NULL);
  BIGNUM *bY = BN_bin2bn(y, 32, NULL);
  if (EC_POINT_set_affine_coordinates_GFp(grp, point, bX, bY, NULL) != 1) {
    return 0;
  }
  if (EC_KEY_set_public_key(ecPKey, point) != 1) {
    return 0;
  }

  EVP_PKEY_assign_EC_KEY(pKey, ecPKey);
  ecPKey = nullptr;

  int keyID = EVP_PKEY_id(pKey);
  EVP_PKEY_METHOD *pkey_meth = EVP_PKEY_meth_new(keyID, 0);
//  EVP_PKEY_ASN1_METHOD *asn1_meth =
//      EVP_PKEY_asn1_new(keyID, ASN1_PKEY_ALIAS, NULL, NULL);
  EVP_PKEY_meth_set_init(pkey_meth, my_pkey_meth_init);
  //  EVP_PKEY_meth_set_cleanup(pkey_meth, my_pkey_meth_cleanup);
  EVP_PKEY_meth_set_copy(pkey_meth, my_pkey_meth_copy);
  EVP_PKEY_meth_set_ctrl(pkey_meth, my_pkey_meth_ctrl, NULL);
  EVP_PKEY_meth_set_sign(pkey_meth, NULL, my_pkey_meth_sign);
//  EVP_PKEY_asn1_set_item(asn1_meth, NULL, item_sign);
  EVP_PKEY_meth_add0(pkey_meth);
//  EVP_PKEY_asn1_add0(asn1_meth);
  X509_REQ *req = X509_REQ_new();
  X509_NAME *subject = X509_NAME_new();
  X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, CHINA_CODE, -1, -1, 0);
  X509_NAME_add_entry_by_txt(subject, "commonName", MBSTRING_ASC, cn, -1, -1, 0);
  X509_REQ_set_version(req, 0L);
  X509_REQ_set_subject_name(req, subject);
  X509_REQ_set_pubkey(req, pKey);

  int iret = X509_REQ_sign(req, pKey, EVP_sm3());
  if (!iret) {
    long err = ERR_get_error();
    printf("req sign err: %s\n", ERR_error_string(err, NULL));
    return err;
  }

  int size = i2d_X509_REQ(req, NULL);
  if (size == 0) {
    return 0;
  }

  unsigned char *reqBytes = (unsigned char *)OPENSSL_malloc(size);
  unsigned char *tempReqBytes = reqBytes;
  i2d_X509_REQ(req, &tempReqBytes);
  BIO* bio_out = BIO_new(BIO_s_mem());
  PEM_write_bio_X509_REQ(bio_out, req);
  BUF_MEM *bio_buf;
  BIO_get_mem_ptr(bio_out, &bio_buf);

  printf("CSR PEM: %s\n", bio_buf->data);
  memcpy(csr, bio_buf->data, bio_buf->length);
  OPENSSL_free(reqBytes);
  BUF_MEM_free(bio_buf);
  X509_NAME_free(subject);
  X509_REQ_free(req);

  return 1;
}

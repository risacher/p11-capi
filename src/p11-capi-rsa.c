/* 
 * Copyright (C) 2008 Stef Walter
 * Copyright (C) 2016 Dan Risacher
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "p11-capi.h"
#include "p11-capi-der.h"
#include "p11-capi-key.h"
#include "p11-capi-object.h"

/* 
 * Portions derived from NSS source files: 
 *     lib/ckfw/capi/crsa.c
 */

/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Red Hat, Inc.
 * Portions created by the Initial Developer are Copyright (C) 2005
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Bob Relyea (rrelyea@redhat.com)
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#define SSL3_SHAMD5_HASH_SIZE  36 /* LEN_MD5 (16) + LEN_SHA1 (20) */

/*
 * PKCS #11 sign for RSA expects to take a fully DER-encoded hash value, 
 * which includes the hash OID. CAPI expects to take a Hash Context. While 
 * CAPI does have the capability of setting a raw hash value, it does not 
 * have the ability to sign an arbitrary value. This function tries to
 * reduce the passed in data into something that CAPI could actually sign.
 */
static CK_BYTE_PTR
parse_rsa_pkcs_der_hash(CK_BYTE_PTR input, CK_ULONG n_input,
                        ALG_ID* algorithm, CK_ULONG_PTR n_hash)
{
  BYTE* algid;
  BYTE* oid;
  BYTE* hash_data;
  BYTE* oid_str;
  DWORD n_oid;
  DWORD n_algid;
  
  p11c_log("parse_rsa_pkcs_der_hash at %s, line %d", __FILE__, __LINE__); 
  p11c_log("n_input %d", n_input); 
  {
    char dbuf[1024];
    char *dbufptr = &dbuf;
    int i;
    for (i=0; i< n_input; i++) {
      dbufptr += sprintf(dbufptr, "%02X", input[i]);
    }
    *dbufptr = 0;
    p11c_log("input: %s", dbuf);
  }
  
  /*
   * there are 2 types of hashes NSS typically tries to sign, regular
   * RSA signature format (with encoded DER_OIDS), and SSL3 Signed hashes.
   * CAPI knows not to add any oids to SSL3_Signed hashes, so if we have any
   * random hash that is exactly the same size as an SSL3 hash, then we can
   * just pass the data through. CAPI has know way of knowing if the value
   * is really a combined hash or some other arbitrary data, so it's safe to
   * handle this case first.
   */
  if(SSL3_SHAMD5_HASH_SIZE == n_input)
    {
      *n_hash = n_input;
      *algorithm = CALG_SSL3_SHAMD5;
      return input;
    }
  
  /* make sure we have a sequence tag */
  if((P11C_DER_SEQUENCE | P11C_DER_CONSTRUCTED) != *input)
    return NULL;
  
  /* 
   * parse the input block to get 1) the hash oid, and 2) the raw hash value.
   * unfortunatly CAPI doesn't have a builtin function to do this work, so
   * we go ahead and do it by hand here.
   *
   * format is:
   *  SEQUENCE {
   *     SECQUENCE { // algid
   *       OID {}    // oid
   *       ANY {}    // optional params 
   *     }
   *     OCTECT {}   // hash
   */
  
  /* unwrap */
  algid = p11c_der_unwrap(input, n_input, &n_algid, NULL);
  if(!algid)
    return NULL;
  
  
  /* make sure there is not extra data at the end */
  if(algid + n_algid != input + n_input)
    return NULL;
  
  /* wasn't an algid */
  if((P11C_DER_SEQUENCE | P11C_DER_CONSTRUCTED) != *algid)
    return NULL;
  
  oid = p11c_der_unwrap(algid, n_algid, &n_oid, &hash_data);
  if(!oid || !hash_data)
    return NULL;
  
  if(algorithm)
    {
      /* 
       * get the real oid as a string. Again, Microsoft does not
       * export anything that does this for us 
       */
      oid_str = p11c_der_read_oid(oid, n_oid);
      if(!oid_str)
        return NULL;
      p11c_log ("oid_str: %s", oid_str);
      
      /* look up the hash alg from the oid (fortunately CAPI does do this) */ 
      *algorithm = CertOIDToAlgId(oid_str);
      p11c_log ("response form CertOIDToAlgId: 0x%x", *algorithm);

      /* The Microsoft Base Smart Card Crypto Provider reports that it
         cannot do SHA-2 algorithms, and that these algorithms are CNG
         only.  I believe that support for these algorithms is
         actually minidriver-dependent.  At the very least, on my
         Windows 8 tablet, with the ActivClient middleware installed,
         I can sucessfuly authenticate with a smart-card client
         certificate using p11-capi, by using the below code to force
         the algorithm to the correct constant, ignoring the result of
         CertOIDToAlgId.  -Dan@Risacher.org, 2016-05-20 */
      
      if (*algorithm == 0xffffffff) {  /* CALG_OID_INFO_CNG_ONLY */
        if (!strncmp("2.16.840.1.101.3.4.2.1", oid_str, 22)) {
          *algorithm = CALG_SHA_256;
          p11c_log("forcing algorithm to CALG_SHA_256 (0x%x)", CALG_SHA_256);
        }
        if (!strncmp("2.16.840.1.101.3.4.2.2", oid_str, 22)) {
          *algorithm = CALG_SHA_256;
          p11c_log("forcing algorithm to CALG_SHA_384 (0x%x)", CALG_SHA_384);
        }
        if (!strncmp("2.16.840.1.101.3.4.2.3", oid_str, 22)) {
          *algorithm = CALG_SHA_256;
          p11c_log("forcing algorithm to CALG_SHA_512 (0x%x)", CALG_SHA_512);
        }
      }
      free(oid_str);
    }
  
  /* wasn't a hash? */
  if(P11C_DER_OCTET_STRING != *hash_data)
    return NULL;
  
  /* get the real raw hash */
  return p11c_der_unwrap(hash_data, n_algid - (hash_data - algid), 
                         n_hash, NULL);
}

CK_RV
p11c_rsa_pkcs_sign_init(P11cObjectData *keydata, void** operation)
{
  CRYPT_KEY_PROV_INFO* prov_info;
  
  ASSERT(keydata);
  ASSERT(operation);
  ASSERT(!*operation);
  
  prov_info = p11c_key_object_data_get_prov_info(keydata);
  if(prov_info->dwProvType != PROV_RSA_FULL)
    return CKR_KEY_TYPE_INCONSISTENT;
  
  *operation = keydata;
  return CKR_OK;
}

CK_RV
p11c_rsa_pkcs_sign_perform (CK_BYTE_PTR data, CK_ULONG n_data,
                            CK_BYTE_PTR signature, CK_ULONG_PTR n_signature,
                            void** operation)
{
  CRYPT_KEY_PROV_INFO* prov_info;
  P11cObjectData* keydata;
  ALG_ID algorithm;
  BYTE* hash_data;
  DWORD n_hash_data;
  BOOL capifail;
  DWORD len, check;
  DWORD bits;
  CK_RV ret;
  
  HCRYPTPROV prov = 0;
  HCRYPTHASH hash = 0;
  
  
  ASSERT(operation);
  ASSERT(*operation);
  
  if(!data || !n_data)
    return CKR_ARGUMENTS_BAD;
  
  keydata = (P11cObjectData*)*operation;
  
  prov_info = p11c_key_object_data_get_prov_info(keydata);
  ASSERT(prov_info);
  
  /* Calculate the number of bits */
  bits = p11c_key_object_data_get_bits (keydata);
  if(!bits) {
    p11c_log("no bits");
    return CKR_GENERAL_ERROR;
  }
  /* Want to know the length */
  if(!signature) 
    {
      *n_signature = bits / 8;
      return CKR_OK;
    }
  
  /* TODO: Support arbitrary input on Vista */
  
  /*
   * PKCS #11 sign for RSA expects to take a fully DER-encoded hash value, 
   * which includes the hash OID. CAPI expects to take a Hash Context. While 
   * CAPI does have the capability of setting a raw hash value, it does not 
   * have the ability to sign an arbitrary value. This function tries to
   * reduce the passed in data into something that CAPI could actually sign.
   */
  hash_data = parse_rsa_pkcs_der_hash(data, n_data, &algorithm, &n_hash_data);
  if(!hash_data) {
    p11c_log("no hash data checkpoint at %s, line %d", __FILE__, __LINE__); 
    return CKR_DATA_INVALID;
  }
  capifail = TRUE;
  if(CryptAcquireContextW(&prov, prov_info->pwszContainerName, prov_info->pwszProvName,
                          prov_info->dwProvType, 0))
    {
      p11c_log("checkpoint at %s, line %d", __FILE__, __LINE__); 
      p11c_log("algorithm 0x%X", algorithm);
      if(CryptCreateHash(prov, algorithm, 0, 0, &hash))
        {
          p11c_log("checkpoint at %s, line %d", __FILE__, __LINE__); 
          /* make sure the hash lens match before we set it */
          len = sizeof(DWORD);
          if(CryptGetHashParam(hash, HP_HASHSIZE, (BYTE*)&check, &len, 0))
            {
              p11c_log("checkpoint at %s, line %d", __FILE__, __LINE__); 
              if(check != n_hash_data) 
                {
                  capifail = FALSE;
                  ret = CKR_DATA_INVALID;
                }
              
              /* 
               * we have an explicit hash, set it, note that the length is
               * implicit by the hashAlg used in create 
               */
              if(CryptSetHashParam(hash, HP_HASHVAL, hash_data, 0))
                {
                  p11c_log("checkpoint at %s, line %d", __FILE__, __LINE__); 
                  /* OK, we have the data in a hash structure, sign it! */
                  if(CryptSignHash(hash, prov_info->dwKeySpec, 
                                   NULL, 0, signature, n_signature))
                    {
                      p11c_log("checkpoint at %s, line %d", __FILE__, __LINE__); 
                      /* 
                       * OK, Microsoft likes to do things completely 
                       * differently than anyone else. We need to reverse 
                       * the data we recieved here 
                       */
                      if(signature)
                        p11c_reverse_memory(signature, *n_signature);
                      
                      capifail = FALSE;
                      ret = CKR_OK;
                    }
                }
            }
        }
    }
  
  if(capifail) {
    p11c_log("capifail %x at %s, line %d", GetLastError(), __FILE__, __LINE__); 
    ret = p11c_winerr_to_ckr(GetLastError());
  }
  if(hash)
    CryptDestroyHash(hash);
  if(prov)
    CryptReleaseContext(prov, 0);
  
  return ret;
}

void
p11c_rsa_pkcs_sign_cleanup (void* operation)
{
  /* Nothing to do */
}


CK_RV
p11c_rsa_pkcs_decrypt_init(P11cObjectData* keydata, void** operation)
{
  CRYPT_KEY_PROV_INFO* prov_info;
  
  ASSERT(keydata);
  ASSERT(operation);
  ASSERT(!*operation);
  
  prov_info = p11c_key_object_data_get_prov_info(keydata);
  if(prov_info->dwProvType != PROV_RSA_FULL)
    return CKR_KEY_TYPE_INCONSISTENT;
  
  *operation = keydata;
  return CKR_OK;
}

CK_RV
p11c_rsa_pkcs_decrypt_perform(CK_BYTE_PTR encdata, CK_ULONG n_encdata,
                              CK_BYTE_PTR result, CK_ULONG_PTR n_result,
                              void** operation)
{
  CRYPT_KEY_PROV_INFO* prov_info;
  P11cObjectData* keydata;
  BOOL capifail;
  DWORD bits, error;
  CK_RV ret;
  
  HCRYPTPROV prov = 0;
  HCRYPTKEY key = 0;
  void* buffer = NULL;
  
  ASSERT(operation);
  ASSERT(*operation);
  ASSERT(encdata);
  ASSERT(n_encdata);
  
  keydata = (P11cObjectData*)*operation;
  
  prov_info = p11c_key_object_data_get_prov_info(keydata);
  ASSERT(prov_info);
  
  /* Calculate the number of bits */
  bits = p11c_key_object_data_get_bits (keydata);
  if(!bits)
    p11c_log("no bits 2");
  return CKR_GENERAL_ERROR;
  
  /* Want to know the length */
  if(!result) 
    {
      *n_result = bits / 8;
      return CKR_OK;
    }
  
  /* 
   * Copy the input, since CAPI operates in place, and 
   * we must also reverse it properly.
   */
  buffer = malloc(n_encdata);
  if(!buffer)
    return CKR_HOST_MEMORY;
  
  memcpy(buffer, encdata, n_encdata);
  p11c_reverse_memory(buffer, n_encdata);
  
  capifail = TRUE;
  if(CryptAcquireContextW(&prov, prov_info->pwszContainerName, prov_info->pwszProvName,
                          prov_info->dwProvType, 0))
    {
      if(CryptGetUserKey(prov, prov_info->dwKeySpec, &key))
        {
          *n_result = n_encdata;
          if(CryptDecrypt(key, 0, TRUE, 0, buffer, n_result))
            {
              capifail = FALSE;
              ret = CKR_OK;
            }
        }
    }
  
  if(capifail)
    {
      error = GetLastError();
      switch(error)
        {
        case NTE_BAD_DATA:
          ret = CKR_ENCRYPTED_DATA_INVALID;
        default:
          p11c_log("failed to acquire context at %s, line %d", __FILE__, __LINE__); 
          
          ret = p11c_winerr_to_ckr(error);
        };
    }
  
  /* Copy the memory out to the result buffer */
  if(ret == CKR_OK)
    ret = p11c_return_data_raw(result, n_result, buffer, *n_result);
  
  if(key)
    CryptDestroyKey(key);
  if(prov)
    CryptReleaseContext(prov, 0);
  if(buffer)
    free(buffer);
  
  return ret;
}

void
p11c_rsa_pkcs_decrypt_cleanup(void* operation)
{
  /* Nothing to do */
}

void
p11c_rsa_pkcs_get_info(CK_MECHANISM_TYPE mech, CK_MECHANISM_INFO_PTR info)
{
  ASSERT(mech == CKM_RSA_PKCS);
  ASSERT(info != NULL);
  
  info->ulMinKeySize = 384;
  info->ulMaxKeySize = 16384;
  info->flags = 0;
}

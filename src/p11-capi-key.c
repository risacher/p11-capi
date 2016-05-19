/* 
 * Copyright (C) 2008 Stef Walter
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
#include "p11-capi-cert.h"
#include "p11-capi-key.h"
#include "p11-capi-object.h"
#include "p11-capi-session.h"
#include "p11-capi-token.h"
#include "x509-usages.h"

typedef struct _KeyObject
{
	P11cObject obj;

	/* The raw key identifier */
	CRYPT_HASH_BLOB key_identifier;
	CK_OBJECT_CLASS object_class;
}
KeyObject;

typedef struct _KeyObjectData
{
	P11cObjectData base;
	CK_OBJECT_CLASS object_class;
	CRYPT_INTEGER_BLOB key_identifier;
	CRYPT_DATA_BLOB raw_public_key;
	CRYPT_KEY_PROV_INFO* prov_info;
	CRYPT_KEY_PROV_INFO* prov_info_aes;
}
KeyObjectData;

static CK_RV
load_key_handle(P11cObjectData* objdata, HCRYPTPROV* ret_prov, 
                HCRYPTKEY* ret_key)
{
	KeyObjectData* kdata = (KeyObjectData*)objdata;
	HCRYPTPROV prov;
	HCRYPTKEY key;
	DWORD error;

	ASSERT(kdata);
	ASSERT(ret_key);
	ASSERT(ret_prov);

	if(!CryptAcquireContextW(&prov, kdata->prov_info->pwszContainerName, 
	                         kdata->prov_info->pwszProvName, 
	                         kdata->prov_info->dwProvType, 0))
	{
          p11c_log("failed to acquire context at %s, line %d", __FILE__, __LINE__);
          p11c_log("Container name %S; provider name %S", 
                   kdata->prov_info->pwszContainerName, 
                   kdata->prov_info->pwszProvName);
          if(!CryptAcquireContextW(&prov, kdata->prov_info->pwszContainerName, 
                                   kdata->prov_info->pwszProvName, 
                                   kdata->prov_info->dwProvType, 
                                   CRYPT_NEWKEYSET)) {
          p11c_log("failed to acquire NEWKEYSET context at %s, line %d", __FILE__, __LINE__);

		return p11c_winerr_to_ckr(GetLastError());
          }
	}

        p11c_log("Container name %S; provider name %S", 
                 kdata->prov_info->pwszContainerName, 
                 kdata->prov_info->pwszProvName);

	if(!CryptGetUserKey(prov, kdata->prov_info->dwKeySpec, &key))
	{
		error = GetLastError();
		CryptReleaseContext(prov, 0);
		return p11c_winerr_to_ckr(error);
	}

	*ret_key = key;
	*ret_prov = prov;

	return CKR_OK;
}


static CK_RV
load_raw_public_key(KeyObjectData* kdata)
{
	BOOL success = FALSE;
	HCRYPTPROV prov;
	HCRYPTKEY key;
	CK_RV ret;
	DWORD error;

	ASSERT(kdata);
	ASSERT(!kdata->raw_public_key.pbData);

	ret = load_key_handle(&kdata->base, &prov, &key);
	if(ret != CKR_OK)
		return ret;

	if(CryptExportKey(key, 0, PUBLICKEYBLOB, 0, NULL, &kdata->raw_public_key.cbData))
	{
		kdata->raw_public_key.pbData = malloc(kdata->raw_public_key.cbData);
		if(!kdata->raw_public_key.pbData)
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		else
		{
			if(CryptExportKey(key, 0, PUBLICKEYBLOB, 0, kdata->raw_public_key.pbData, 
			                  &kdata->raw_public_key.cbData))
			{
				success = TRUE;
			}
		}
	}

	CryptReleaseContext(prov, 0);
	CryptDestroyKey(key);

	if(success)
	{
		return CKR_OK;
	}
	else
	{
		error = GetLastError();
		if(error == NTE_BAD_KEY_STATE)
			return CKR_ATTRIBUTE_SENSITIVE;
		return p11c_winerr_to_ckr(error);
	}
}

static CK_RV
lookup_rsa_attribute(KeyObjectData* kdata, CK_ATTRIBUTE_PTR attr)
{
	PUBLICKEYSTRUC* header;
	RSAPUBKEY* pubkey;
	CK_ULONG number;
	CK_RV ret;

	ASSERT(kdata);
	ASSERT(attr);

	if(!kdata->raw_public_key.pbData)
	{
		ret = load_raw_public_key(kdata);
		if(ret != CKR_OK)
			return ret;
	}

	header = (PUBLICKEYSTRUC*)kdata->raw_public_key.pbData;
	if(!header->bType == PUBLICKEYBLOB) {
                p11c_log("header type not PUBLICKEYBLOB");
		return CKR_GENERAL_ERROR;
        }
	pubkey = (RSAPUBKEY*)(header + 1);
	if(!pubkey->magic == 0x31415352) {
                p11c_log("pubkey magic wrong");
		return CKR_GENERAL_ERROR;
        }
	switch(attr->type) 
	{
	case CKA_MODULUS_BITS:
		number = pubkey->bitlen;
		return p11c_return_data(attr, &number, sizeof(CK_ULONG));

	case CKA_PUBLIC_EXPONENT:
		return p11c_return_dword_as_bytes(attr, pubkey->pubexp);

	case CKA_MODULUS:
		return p11c_return_reversed_data(attr, (pubkey + 1), 
		                                 pubkey->bitlen / 8);

	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
		if(kdata->object_class == CKO_PRIVATE_KEY)
			return CKR_ATTRIBUTE_SENSITIVE;
		else
			return CKR_ATTRIBUTE_TYPE_INVALID;

	default:
		ASSERT(FALSE);
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}

static CK_RV
key_bool_attribute(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr)
{
	KeyObjectData* kdata = (KeyObjectData*)objdata;
	CK_BBOOL val;
	CK_BBOOL is_private, is_rsa;

	ASSERT(objdata);
	ASSERT(attr);

	is_private = (kdata->object_class == CKO_PRIVATE_KEY);
	is_rsa = kdata->prov_info->dwProvType == PROV_RSA_FULL;

	switch(attr->type) 
	{

	/* 
	 * Whether to authenticate before every use.
	 * - CAPI does all authentication
	 */
	case CKA_ALWAYS_AUTHENTICATE:
		val = CK_FALSE;
		break;

	/*
	 * Whether this key has always been sensitive.
	 * TODO: Can we detect this?
	 */
	case CKA_ALWAYS_SENSITIVE:
		val = CK_FALSE;
		break;

	/* 
	 * Whether this key can be used to decrypt.
	 * - CKK_RSA but not CKK_DSA.
	 */
	case CKA_DECRYPT:
		val = is_private && is_rsa;
		break;

	/* 
	 * Whether this key can be used to derive a session or 
	 * other key.
	 * - Not true for CKK_RSA or CKK_DSA.
	 */
	case CKA_DERIVE:
		val = CK_FALSE;
		break;

	/*
	 * Whether or not this key can be used to encrypt?.
	 * TODO: Support for RSA public keys.
	 */
	case CKA_ENCRYPT:
		val = CK_FALSE;
		break;

	/*
	 * Whether this key can be exported or not.
	 * TODO: We may want to support this for public keys.
	 */
	case CKA_EXTRACTABLE:
		val = CK_FALSE;
		break;

	/*
	 * Whether this key was created on token.
	 * TODO: Can we implement this properly?
	 */
	case CKA_LOCAL:
		val = CK_FALSE;
		break;

	/*
	 * Whether this object is modifiable.
	 * - Keys are generally. never modifiable.
	 */
	case CKA_MODIFIABLE:
		val = CK_FALSE;
		break;

	/*
	 * Whether this key was ever extractable.
	 * TODO: Can we determine this?
	 */
	case CKA_NEVER_EXTRACTABLE:
		val = CK_FALSE;
		break;

	/*
	 * Whether this is a private object or not.
	 * - This 'private' means login before use. But maps
	 *   well to private key use, since we're always logged in.
	 */
	case CKA_PRIVATE:
		val = is_private;
		break;

	/*
	 * Whether this is a sensitive object or not.
	 * - Private keys are sensitive, some attributes not 
	 *   readable.
	 */
	case CKA_SENSITIVE:
		val = is_private;
		break;

	/* 
	 * Can this key sign stuff? 
	 * - Private keys can sign.
	 */
	case CKA_SIGN:
		val = is_private;
		break;

	/*
	 * Can this key sign recoverable.
	 * TODO: Private RSA keys can sign recoverable.
	 */
	case CKA_SIGN_RECOVER:
		val = CK_FALSE;
		break;

	/*
	 * Is this stored on the token?
	 * - All CAPI objects are.
	 */
	case CKA_TOKEN:
		val = CK_TRUE;
		break;

	/* 
	 * Is this key trusted? 
	 * - A nebulous question.
	 */
	case CKA_TRUSTED:
		val = CK_FALSE;
		break;

	/*
	 * Key wrapping with public keys.
	 */
	case CKA_WRAP:
		if(is_private)
			return CKR_ATTRIBUTE_TYPE_INVALID;
		val = CK_FALSE;
		break;

	/*
	 * Key wrapping on private keys. 
	 */
	case CKA_WRAP_WITH_TRUSTED:
		if(!is_private)
			return CKR_ATTRIBUTE_TYPE_INVALID;
		val = CK_FALSE;
		break;

	/*
	 * Can do a unwrap operation?
	 * - We don't implement this.
	 */
	case CKA_UNWRAP:
		val = CK_FALSE;
		break;

	/*
	 * Wrap, and unwrap stuff.
	 * - We don't implement this.
	 */
	case CKA_UNWRAP_TEMPLATE:
		return CKR_ATTRIBUTE_TYPE_INVALID;

	/*
	 * Whether this key can be used to verify?
	 * TODO: Support for public keys.
	 */
	case CKA_VERIFY:
		val = CK_FALSE;
		break;

	/*
	 * Whether this key can be used to verify?
	 * TODO: Support for public keys.
	 */
	case CKA_VERIFY_RECOVER:
		val = CK_FALSE;
		break;

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};

	return p11c_return_data(attr, &val, sizeof(CK_BBOOL));
}

static CK_RV
key_ulong_attribute(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr)
{
	KeyObjectData* kdata = (KeyObjectData*)objdata;
	CK_ULONG val;

	ASSERT(kdata);
	ASSERT(attr);

	switch(attr->type)
	{

	/*
	 * Object class.
	 */
	case CKA_CLASS:
		val = kdata->object_class;
		break;

	/*
	 * The key type.
	 * - Right now we only support (and load) RSA.
	 */
	case CKA_KEY_TYPE:
		if(kdata->prov_info->dwProvType == PROV_RSA_FULL)
			val = CKK_RSA;
		else
			val = CK_UNAVAILABLE_INFORMATION;
		break;

	/* 
	 * The key generation mechanism. 
	 * TODO: We don't yet support key generation.
	 */
	case CKA_KEY_GEN_MECHANISM:
		val = CK_UNAVAILABLE_INFORMATION;
		break;

	/* 
	 * The RSA modulus bits.
	 */
	case CKA_MODULUS_BITS:
		if(kdata->prov_info->dwProvType == PROV_RSA_FULL)
			return lookup_rsa_attribute(kdata, attr);
		else
			return CKR_ATTRIBUTE_TYPE_INVALID;

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};

	return p11c_return_data(attr, &val, sizeof(CK_ULONG));
}

static CK_RV
key_bytes_attribute(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr)
{
	KeyObjectData* kdata = (KeyObjectData*)objdata;
	CK_MECHANISM_TYPE allowed_mechanisms[] = { CKM_RSA_PKCS };
	WCHAR* label;

	ASSERT(kdata);
	ASSERT(attr);

	switch(attr->type)
	{
	/*
	 * The ID of the key. This should match the ID we 
	 * return for any matching certificates.
	 */
	case CKA_ID:
		return p11c_return_data(attr, kdata->key_identifier.pbData, 
		                        kdata->key_identifier.cbData);

	/*
	 * The key label. 
	 * - We use the container name.
	 */
	case CKA_LABEL:
		label = kdata->prov_info->pwszContainerName;
		if(!label)
			label = L"Unnamed Key";
		return p11c_return_string(attr, label);

	/* 
	 * The subject of the related certificate.
	 * TODO: Implement this lookup.
	 */
	case CKA_SUBJECT:
		return p11c_return_data(attr, "", 0);

	/*
	 * Allowed mechanisms with this key.
	 * - RSA used with CKM_RSA
	 * TODO: Needs updating when DSA implemented.
	 */
	case CKA_ALLOWED_MECHANISMS:
		return p11c_return_data(attr, &allowed_mechanisms, 
		                          sizeof(allowed_mechanisms));

	/*
	 * Various RSA public attributes.
	 */
	case CKA_MODULUS:
	case CKA_PUBLIC_EXPONENT:
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
		if(kdata->prov_info->dwProvType == PROV_RSA_FULL)
			return lookup_rsa_attribute(kdata, attr);
		else
			return CKR_ATTRIBUTE_TYPE_INVALID;

	/* 
	 * Last date this key can be used. 
	 * TODO: Does CAPI support this ability?
	 */
	case CKA_END_DATE:
	case CKA_START_DATE:
		return p11c_return_data(attr, "", 0);

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
}

static void
key_release(void* data)
{
	KeyObjectData* kdata = (KeyObjectData*)data;
	ASSERT(kdata);

	ASSERT(kdata->key_identifier.pbData);
	ASSERT(kdata->prov_info);

	free(kdata->key_identifier.pbData);
	free(kdata->prov_info);

	free(kdata);
}

static const P11cObjectDataVtable key_objdata_vtable = {
	key_bool_attribute,
	key_ulong_attribute,
	key_bytes_attribute,
	key_release,
};

static CRYPT_KEY_PROV_INFO*
duplicate_prov_info(CRYPT_KEY_PROV_INFO* original)
{
	DWORD container_length, prov_length;
	CRYPT_KEY_PROV_INFO* result;
	DWORD length, i;
	BYTE* at;
	BYTE* end;
	
	if(!original)
		return NULL;

	/* Go through and calculate the length */
	length = sizeof(CRYPT_KEY_PROV_INFO);
	if(original->pwszContainerName)
	{
		container_length = (wcslen(original->pwszContainerName) + 1) * sizeof(WCHAR);
		length += container_length;
	}

	if(original->pwszProvName)
	{
		prov_length = (wcslen(original->pwszProvName) + 1) * sizeof(WCHAR);
		length += prov_length;
	}

	length += sizeof(CRYPT_KEY_PROV_PARAM) * original->cProvParam;
	for(i = 0; i < original->cProvParam; ++i) 
		length += original->rgProvParam[i].cbData;

	/* Allocate a single block of memory for everything */
	at = (BYTE*)malloc(length);
	if(!at)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return NULL;
	}

	/* Copy in very carefully */
	end = at + length;
	
	memcpy(at, original, sizeof(CRYPT_KEY_PROV_INFO));
	result = (CRYPT_KEY_PROV_INFO*)at;
	at += sizeof(CRYPT_KEY_PROV_INFO);

	if(result->pwszContainerName)
	{
          p11c_log("copying container name %S", original->pwszContainerName);
		memcpy(at, result->pwszContainerName, container_length);
		result->pwszContainerName = (LPWSTR)at;
		at += container_length;
	}

	if(result->pwszProvName)
	{
		memcpy(at, result->pwszProvName, prov_length);
		result->pwszProvName = (LPWSTR)at;
		at += prov_length;
	}

	if(original->cProvParam)
	{
		memcpy(at, result->rgProvParam, sizeof(CRYPT_KEY_PROV_PARAM) * result->cProvParam);
		result->rgProvParam = (CRYPT_KEY_PROV_PARAM*)at;
		at += sizeof(CRYPT_KEY_PROV_PARAM) * result->cProvParam;

		for(i = 0; i < result->cProvParam; ++i)
		{
			memcpy(at, result->rgProvParam[i].pbData, result->rgProvParam[i].cbData);
			result->rgProvParam[i].pbData = (BYTE*)at;
			at += result->rgProvParam[i].cbData;
		}
	}

	ASSERT(at == end);
	return result;
}

static P11cObjectData*
key_alloc_data(P11cSession* sess, P11cObject* obj, CRYPT_KEY_PROV_INFO* prov_info)
{
	KeyObject* kobj = (KeyObject*)obj;
	KeyObjectData* kdata;

	kdata = (KeyObjectData*)calloc(1, sizeof(KeyObjectData));
	if(!kdata)
		return NULL;

	/* Allocate memory for key identifier */
	kdata->key_identifier.pbData = malloc(kobj->key_identifier.cbData);
	if(!kdata->key_identifier.pbData)
	{
		free(kdata);
		return NULL;
	}

	/* Setup the object data */
	kdata->object_class = kobj->object_class;
	kdata->prov_info = prov_info;
	kdata->key_identifier.cbData = kobj->key_identifier.cbData;
	memcpy(kdata->key_identifier.pbData, kobj->key_identifier.pbData,
	       kdata->key_identifier.cbData);
	kdata->raw_public_key.pbData = NULL;
	kdata->raw_public_key.cbData = 0;

	kdata->base.object = obj->id;
	kdata->base.data_funcs = &key_objdata_vtable;
        
        // Attempt to get the Enhanced RSA and AES Cryptographic Provider.
        CryptAcquireContext(kdata->prov_info_aes, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0);


	return &(kdata->base);
}

static BOOL WINAPI
load_key_property_info(PCRYPT_HASH_BLOB key_identifier, DWORD flags, 
                       void* reserved, void* arg, DWORD n_props, DWORD* props,
                       void** datas, DWORD* n_datas)
{
	CRYPT_KEY_PROV_INFO** prov_info = (CRYPT_KEY_PROV_INFO**)arg;
	DWORD i;

	/* 
	 * Already got a provider info. This shouldn't happen
	 * but can occur if the same key is present twice.
	 */
	if(*prov_info)
		return TRUE;

	/* Find the key provider info property */
	for(i = 0; i < n_props; ++i)
	{
		if(props[i] == CERT_KEY_PROV_INFO_PROP_ID)
		{
			*prov_info = duplicate_prov_info((CRYPT_KEY_PROV_INFO*)datas[i]);
			break;
		}
	}

	return TRUE;
}

static CK_RV 
key_load_data(P11cSession* sess, P11cObject* obj, P11cObjectData** objdata)
{
	KeyObject* kobj = (KeyObject*)obj;
	CRYPT_KEY_PROV_INFO* prov_info = NULL;

	ASSERT(kobj);
	ASSERT(objdata);

	/* Load the provider info */
	if(!CryptEnumKeyIdentifierProperties((CRYPT_HASH_BLOB*)&kobj->key_identifier, 
	                                     CERT_KEY_PROV_INFO_PROP_ID, 0, NULL, NULL,
	                                     &prov_info, load_key_property_info))
		return p11c_winerr_to_ckr(GetLastError());

	/* No provider info, bad news */
	if(!prov_info) {
          p11c_log("No provider info, bad news");

		return CKR_GENERAL_ERROR;
	}
	*objdata = key_alloc_data(sess, obj, prov_info);
	if(!(*objdata))
	{
		free(prov_info);
		return CKR_HOST_MEMORY;
	}

	return CKR_OK;
}

static unsigned int
key_hash_func(P11cObject* obj)
{
	KeyObject* kobj = (KeyObject*)obj;
	return p11c_hash_data(kobj->key_identifier.pbData, kobj->key_identifier.cbData) ^
	       p11c_hash_integer((int)kobj->object_class);
}

static int
key_equal_func(P11cObject* a, P11cObject* b)
{
	KeyObject* ka = (KeyObject*)a;
	KeyObject* kb = (KeyObject*)b;
	return ka->object_class == kb->object_class && 
	       ka->key_identifier.cbData == kb->key_identifier.cbData && 
	       memcmp(ka->key_identifier.pbData, kb->key_identifier.pbData, ka->key_identifier.cbData) == 0;
}

static void 
key_object_release(void* data)
{
	KeyObject* kobj = (KeyObject*)data;
	ASSERT(kobj);
	free(kobj);
}

static const P11cObjectVtable key_object_vtable = {
	key_load_data,
	key_hash_func,
	key_equal_func,
	key_object_release,
};

static CK_RV
register_key_object(P11cSession* sess, CK_OBJECT_CLASS cls,
                    CRYPT_HASH_BLOB* key_identifier, P11cObject** obj)
{
	KeyObject* kobj;
	CK_RV ret;

	ASSERT(obj);
	ASSERT(key_identifier);
	ASSERT(cls == CKO_PRIVATE_KEY || cls == CKO_PUBLIC_KEY);

	kobj = calloc(1, sizeof(KeyObject) + key_identifier->cbData);
	if(!kobj)
		return CKR_HOST_MEMORY;

	kobj->obj.id = 0;
	kobj->obj.obj_funcs = &key_object_vtable;

	kobj->object_class = cls;
	kobj->key_identifier.pbData = (BYTE*)(kobj + 1);
	kobj->key_identifier.cbData = key_identifier->cbData;
	memcpy(kobj->key_identifier.pbData, key_identifier->pbData,
	       kobj->key_identifier.cbData);

	ret = p11c_token_register_object(sess->slot, &(kobj->obj));
	if(ret != CKR_OK)
	{
		free(kobj);
		return ret;
	}

	ASSERT(kobj->obj.id != 0);
	*obj = &(kobj->obj);

	return CKR_OK;
}

typedef struct _EnumArguments 
{
	P11cSession* sess;
	CK_OBJECT_CLASS object_class;
	CK_ATTRIBUTE_PTR match;
	CK_ULONG count;
	P11cArray* results;
	CK_RV ret;
}
EnumArguments;

static BOOL WINAPI
enum_key_property_info(PCRYPT_HASH_BLOB key_identifier, DWORD flags, 
                       void* reserved, void* arg, DWORD n_props, DWORD* props,
                       void** datas, DWORD* n_datas)
{
	EnumArguments* args = (EnumArguments*)arg;
	CRYPT_KEY_PROV_INFO* prov_info = NULL;
	P11cObject *obj = NULL;
	KeyObjectData kdata;
	DWORD i;

	/* Find the key provider info property */
	for(i = 0; i < n_props; ++i)
	{
		if(props[i] == CERT_KEY_PROV_INFO_PROP_ID)
		{
			prov_info = (CRYPT_KEY_PROV_INFO*)datas[i];
			break;
		}
	}

	/* Strange key, skip */
	if(!prov_info)
		return TRUE;

	/* Match the public key */
	kdata.prov_info = prov_info;
	kdata.object_class = args->object_class;
	kdata.base.object = 0;
	kdata.base.data_funcs = &key_objdata_vtable;

	if(p11c_object_data_match(&kdata.base, args->match, args->count))
	{
		args->ret = register_key_object(args->sess, args->object_class, key_identifier, &obj);
		if(args->ret == CKR_OK)
		{
			ASSERT(obj);
			p11c_array_append(args->results, obj->id);
		}
	}

	return TRUE;

}

static CK_RV
find_any_keys(P11cSession* sess, CK_OBJECT_CLASS cls,
              CK_ATTRIBUTE_PTR match, CK_ULONG count, P11cArray* arr)
{
	CRYPT_HASH_BLOB find_id;
	EnumArguments enum_args;
	CK_ULONG i;

	/* Try to setup for an efficient search based on key id */
	memset(&find_id, 0, sizeof(find_id));
	for(i = 0; i < count; ++i)
	{
		if(!match[i].pValue || !match[i].ulValueLen)
			continue;
		if(match[i].type == CKA_ID)
		{
			find_id.cbData = match[i].ulValueLen;
			find_id.pbData = match[i].pValue;
		}
	}

	enum_args.sess = sess;
	enum_args.match = match;
	enum_args.count = count;
	enum_args.results = arr;
	enum_args.object_class = cls;
	enum_args.ret = CKR_OK;

	if(!CryptEnumKeyIdentifierProperties(find_id.cbData != 0 ? &find_id : NULL, 
	                                     CERT_KEY_PROV_INFO_PROP_ID, 0, NULL, NULL,
	                                     &enum_args, enum_key_property_info))
		return p11c_winerr_to_ckr(GetLastError());

	return enum_args.ret;
}

static CK_RV
list_matching_certificates(P11cSession* sess, CK_ATTRIBUTE_PTR match, 
                           CK_ULONG count, P11cArray* arr)
{
	CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE search[3];
	CK_ULONG n_search = 0;
	CK_ULONG i;

	/* The class */
	search[0].type = CKA_CLASS;
	search[0].pValue = &cert_class;
	search[0].ulValueLen = sizeof(CK_OBJECT_CLASS);
	++n_search;

	for(i = 0; i < count && n_search < 3; ++i)
	{
		/* 
		 * This is the attributes that tie a certificate 
		 * to key object, so try match certs with these
		 */
		if(match[i].type == CKA_ID)
		{
			search[n_search].type = match[i].type;
			search[n_search].pValue = match[i].pValue;
			search[n_search].ulValueLen = match[i].ulValueLen;
			++n_search;
		}
	}

	/* Do the certificate search */
	return p11c_cert_find(sess, CKO_CERTIFICATE, search, n_search, arr);
}

static CK_RV
find_certificate_key(P11cSession* session, CK_OBJECT_CLASS cls,
                     CK_ATTRIBUTE_PTR match, CK_ULONG count, 
                     PCCERT_CONTEXT cert, P11cArray* arr)
{
	CRYPT_KEY_PROV_INFO* prov_info;
	CRYPT_HASH_BLOB key_identifier;
	P11cObjectData* objdata;
	KeyObjectData kdata;
	P11cObject* obj;
	DWORD prov_length;
	DWORD error;
	CK_RV ret = CKR_OK;

	/* Look up the key provider info and identifier */
	if(!CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &prov_length) ||
	   !CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, NULL, &key_identifier.cbData))
	{
		error = GetLastError();
		if(error == CRYPT_E_NOT_FOUND)
			return CKR_OK;
		return p11c_winerr_to_ckr(error);
	}

	/* We own the info memory */
	prov_info = malloc(prov_length);
	if(!prov_info)
		return CKR_HOST_MEMORY;
	key_identifier.pbData = malloc(key_identifier.cbData);
	if(!key_identifier.pbData)
	{
		free(prov_info);
		return CKR_HOST_MEMORY;
	}

	/* Lookup the key provider info and identifier */
	if(CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, prov_info, &prov_length) &&
	   CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, key_identifier.pbData, &key_identifier.cbData))
	{
		kdata.object_class = cls;
		kdata.prov_info = prov_info;
		kdata.key_identifier = key_identifier;
		kdata.base.object = 0;
		kdata.base.data_funcs = &key_objdata_vtable;

		if(p11c_object_data_match(&kdata.base, match, count))
		{
			ret = register_key_object(session, cls, &key_identifier, &obj);
			if(ret == CKR_OK)
			{
				ASSERT(obj);

				/* Store away the object data for performance reasons */
				objdata = key_alloc_data(session, obj, prov_info);
				if(objdata)
				{
					p11c_session_take_object_data(session, obj, objdata);

					/* Note these are used, and not to be freed */
					key_identifier.pbData = NULL;
					key_identifier.cbData = 0;
					prov_info = NULL;
				}

				p11c_array_append(arr, obj->id);
			}
		}
	}
	else
	{
		ret = p11c_winerr_to_ckr(GetLastError());
	}

	if(key_identifier.pbData)
		free(key_identifier.pbData);
	if(prov_info)
		free(prov_info);

	return ret;
}

static CK_RV
find_certificate_keys(P11cSession* session, CK_OBJECT_CLASS cls,
                      CK_ATTRIBUTE_PTR match, CK_ULONG count, P11cArray* arr)
{
	CK_OBJECT_HANDLE id;
	P11cObjectData* certdata;
	P11cArray* certarr;
	PCCERT_CONTEXT cert;
	CK_RV ret = CKR_OK;
	CK_ULONG i;

	/* Get a list of all certificates */
	certarr = p11c_array_new(0, 1, sizeof(CK_OBJECT_HANDLE));
	if(!certarr)
		return CKR_HOST_MEMORY;
	ret = list_matching_certificates(session, match, count, certarr);

	/* Now match each of them against our criteria */
	if(ret == CKR_OK)
	{
		for(i = 0; i < certarr->len; ++i)
		{
			id = p11c_array_index(certarr, CK_OBJECT_HANDLE, i);
			ASSERT(id);

			/* Get the certificate data for this certificate object */
			if(p11c_session_get_object_data_for(session, id, &certdata) != CKR_OK)
				continue;

			/* Get the certificate context */
			cert = p11c_cert_object_data_get_certificate(certdata);
			if(!cert)
				continue;

			/* Remember we can have either or both keys for each certificate */
			ret = find_certificate_key(session, cls, match, count, cert, arr);
		}
	}

	p11c_array_free(certarr, TRUE);
	return ret;
}

CK_RV
p11c_key_find(P11cSession* sess, CK_OBJECT_CLASS cls, 
              CK_ATTRIBUTE_PTR match, CK_ULONG count, P11cArray* arr)
{
	CK_RV ret = CKR_OK;

	/* Is this somewhere we have all keys present? */
	if(p11c_token_get_flags(sess->slot) & P11C_SLOT_ANYKEY)
	{
		if((cls == CKO_PRIVATE_KEY || cls == CKO_ANY) && ret == CKR_OK)
			ret = find_any_keys(sess, CKO_PRIVATE_KEY, match, count, arr);
		if((cls == CKO_PUBLIC_KEY || cls == CKO_ANY) && ret == CKR_OK)
			ret = find_any_keys(sess, CKO_PUBLIC_KEY, match, count, arr);
	}

	/* Otherwise we can only list the keys that have certificates */
	else
	{
		if((cls == CKO_PRIVATE_KEY || cls == CKO_ANY) && ret == CKR_OK)
			ret = find_certificate_keys(sess, CKO_PRIVATE_KEY, match, count, arr);
		if((cls == CKO_PUBLIC_KEY || cls == CKO_ANY) && ret == CKR_OK)
			ret = find_certificate_keys(sess, CKO_PUBLIC_KEY, match, count, arr);
	}

	return ret;
}

DWORD
p11c_key_object_data_get_bits(P11cObjectData* objdata)
{
	KeyObjectData* kdata;
	PUBLICKEYSTRUC* header;
	RSAPUBKEY* pubkey;
	CK_RV ret;

	ASSERT(objdata);

	kdata = (KeyObjectData*)objdata;
	
	if(!kdata->raw_public_key.pbData)
	{
		ret = load_raw_public_key(kdata);
		if(ret != CKR_OK)
			return ret;
	}

	header = (PUBLICKEYSTRUC*)kdata->raw_public_key.pbData;
	if(!header->bType == PUBLICKEYBLOB)
		return 0;

	pubkey = (RSAPUBKEY*)(header + 1);
	if(!pubkey->magic == 0x31415352)
		return 0;

	return pubkey->bitlen;
}

CRYPT_KEY_PROV_INFO*
p11c_key_object_data_get_prov_info(P11cObjectData* objdata)
{
	KeyObjectData* kdata;

	ASSERT(objdata);
	kdata = (KeyObjectData*)objdata;
	return kdata->prov_info;
}

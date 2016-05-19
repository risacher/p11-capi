/* 
 * Copyright (C) 2007 Stef Walter
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
#include "p11-capi-object.h"
#include "p11-capi-session.h"
#include "p11-capi-token.h"

#include <memory.h>

#ifndef CERT_FIND_KEY_IDENTIFIER
#define CERT_FIND_KEY_IDENTIFIER 983040
#endif

#ifndef CERT_KEY_IDENTIFIER_PROP_ID
#define CERT_KEY_IDENTIFIER_PROP_ID	20
#endif 

typedef struct _CertObject
{
	P11cObject obj;

	/* Together these can uniquely identify a certificate */
	CRYPT_INTEGER_BLOB serial;
	CERT_NAME_BLOB issuer;
}
CertObject;

typedef struct _CertObjectData
{
	P11cObjectData base;
	PCCERT_CONTEXT cert;
	BOOL is_in_root;
}
CertObjectData;

static CK_RV
parse_basic_constraints(CertObjectData* cdata, CK_ULONG* category)
{
	CERT_BASIC_CONSTRAINTS_INFO* basic;
	CERT_EXTENSION* ext;
	DWORD size;
	BYTE bits;
	CK_RV ret;

	ASSERT(cdata);
	ASSERT(cdata->cert);

	*category = 0;

	ext = CertFindExtension(szOID_BASIC_CONSTRAINTS, 
	                        cdata->cert->pCertInfo->cExtension,
	                        cdata->cert->pCertInfo->rgExtension);

	/* No key usage, don't care */
	if(!ext)
		return CKR_OK;

	/* Find the size of the decoded structure */
	if(!CryptDecodeObject(P11c_ENCODINGS, X509_BASIC_CONSTRAINTS, 
	                      ext->Value.pbData, ext->Value.cbData, 0, NULL, &size))
		return p11c_winerr_to_ckr(GetLastError());

	/* Allocate enough memory */
	basic = (CERT_BASIC_CONSTRAINTS_INFO*)calloc(1, size);
	if(!basic)
		return CKR_HOST_MEMORY;

	/* And get the decoded structure */
	if(CryptDecodeObject(P11c_ENCODINGS, X509_BASIC_CONSTRAINTS, 
	                     ext->Value.pbData, ext->Value.cbData, 0, basic, &size))
	{
		if(basic->SubjectType.cbData != 1)
		{
			WARN(("basic constraints bits are of invalid size"));
                        p11c_log("basic constraints bits are of invalid size");
			ret = CKR_GENERAL_ERROR;
		}
		else
		{
			/* All of the above was for 2 bits. Lovely */
			bits = basic->SubjectType.pbData[0] & ~(0xff >> (8 - basic->SubjectType.cUnusedBits));
			if((bits & CERT_CA_SUBJECT_FLAG) == CERT_CA_SUBJECT_FLAG)
				*category = 2;
			else if((bits & CERT_END_ENTITY_SUBJECT_FLAG) == CERT_END_ENTITY_SUBJECT_FLAG)
				*category = 3;
			else
				*category = 0;
			ret = CKR_OK;
		}
	}
	else
	{
		ret = p11c_winerr_to_ckr(GetLastError());
	}

	free(basic);

	return ret;
}


static CK_RV
cert_bool_attribute(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr)
{
	CertObjectData* cdata = (CertObjectData*)objdata;
	CK_BBOOL val;

	ASSERT(cdata);

	switch(attr->type) 
	{
	/* 
	 * Resides on the token
	 * - Always true for CAPI objects.
	 */
	case CKA_TOKEN:
		val = CK_TRUE;
		break;

	/*
	 * Private vs. Public object.
	 * - Always false for certificates.
	 */
	case CKA_PRIVATE:
		val = CK_FALSE;
		break;

	/*
	 * If object can be modified.
	 * - Currently always false. In the future with additional 
	 *   functionality this may change.
	 */
	case CKA_MODIFIABLE:
		val = CK_FALSE;
		break;

	/*
	 * Whether the certificate can be trusted for the application
	 * in which it was created.
	 * - We just report on whether the certificate is a trusted root.
	 */
	case CKA_TRUSTED:
		val = cdata->is_in_root ? CK_TRUE : CK_FALSE;
		break;

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};

	return p11c_return_data(attr, &val, sizeof(CK_BBOOL));
}

static CK_RV
cert_ulong_attribute(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr)
{
	CertObjectData* cdata = (CertObjectData*)objdata;
	CK_ULONG val;
	CK_RV ret;

	ASSERT(objdata);

	switch(attr->type)
	{

	/*
	 * Object class.
	 * - Always CKO_CERTIFICATE for certificates.
	 */
	case CKA_CLASS:
		val = CKO_CERTIFICATE;
		break;

	/*
	 * Type of certificate. 
	 * - Always X509.
	 */
	case CKA_CERTIFICATE_TYPE:
		val = CKC_X_509;
		break;

	/*
	 * Whether a CA, user certificate, other.
	 * - Get certificate szOID_ENHANCED_KEY_USAGE 
	 * extension or CERT_CTL_PROP_ID and look into CTL_USAGE structure.
	 */
	case CKA_CERTIFICATE_CATEGORY:
		ret = parse_basic_constraints(cdata, &val);
		if(ret != CKR_OK)
			return ret;
		break;

	/* 
	 * Java MIDP security domain.
	 * - Have no idea what this is. Spec says default to zero.
	 */
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
		val = 0;
		break;

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};

	return p11c_return_data(attr, &val, sizeof(CK_ULONG));
}

static CK_RV
cert_bytes_attribute(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr)
{
	CertObjectData* cdata = (CertObjectData*)objdata;
	PCCERT_CONTEXT cert = cdata->cert;
			
	ASSERT(sizeof(CK_ULONG) == sizeof(DWORD));
	ASSERT(cdata);

	return p11c_cert_certificate_get_bytes(cdata->cert, attr);
}

static void
cert_data_release(void* data)
{
	CertObjectData* cdata = (CertObjectData*)data;
	ASSERT(cdata && cdata->cert);
	CertFreeCertificateContext(cdata->cert);
	free(cdata);
}

static const P11cObjectDataVtable cert_objdata_vtable = {
	cert_bool_attribute,
	cert_ulong_attribute,
	cert_bytes_attribute,
	cert_data_release,
};

static P11cObjectData*
cert_alloc_data(P11cSession* sess, P11cObject* obj, PCCERT_CONTEXT cert)
{
	CertObjectData* cdata;

	cdata = (CertObjectData*)calloc(1, sizeof(CertObjectData));
	if(!cdata)
		return NULL;
	
	cdata->cert = cert;
	cdata->is_in_root = (p11c_token_get_flags(sess->slot) & P11C_SLOT_CA) ? TRUE : FALSE;

	cdata->base.object = obj->id;
	cdata->base.data_funcs = &cert_objdata_vtable;

	return &(cdata->base);
}

static CK_RV 
cert_load_data(P11cSession* sess, P11cObject* obj, P11cObjectData** objdata)
{
	CertObject* cobj = (CertObject*)obj;
	CERT_INFO info;
	PCCERT_CONTEXT cert;

	ASSERT(cobj);
	ASSERT(objdata);

	ASSERT(cobj->issuer.pbData);
	ASSERT(cobj->issuer.cbData);
	ASSERT(cobj->serial.pbData);
	ASSERT(cobj->serial.cbData);

	/* No store should mean no objects were loaded */
	ASSERT(sess->store);

	/* Setup our search */
	memset(&info, 0, sizeof(info));
	memcpy(&info.SerialNumber, &cobj->serial, sizeof(info.SerialNumber));
	memcpy(&info.Issuer, &cobj->issuer, sizeof(info.Issuer));

	cert = CertGetSubjectCertificateFromStore(sess->store, P11c_ENCODINGS, &info);

	if(!cert)
	{
		DWORD err = GetLastError();

		/* TODO: Is this right for a deleted certificate? */
		ASSERT(err != E_INVALIDARG);
		if(err == CRYPT_E_NOT_FOUND)
			return CKR_OBJECT_HANDLE_INVALID;
		else
			return p11c_winerr_to_ckr(GetLastError());
	}

	*objdata = cert_alloc_data(sess, obj, cert);
	if(!(*objdata))
	{
		CertFreeCertificateContext(cert);
		return CKR_HOST_MEMORY;
	}
	
	return CKR_OK;
}

static unsigned int
cert_hash_func(P11cObject* obj)
{
	CertObject* cobj = (CertObject*)obj;
	return p11c_hash_data(cobj->issuer.pbData, cobj->issuer.cbData) ^
	       p11c_hash_data(cobj->serial.pbData, cobj->serial.cbData);
}

static int
cert_equal_func(P11cObject* a, P11cObject* b)
{
	CertObject* ca = (CertObject*)a;
	CertObject* cb = (CertObject*)b;
	return ca->issuer.cbData == cb->issuer.cbData && 
	       memcmp(ca->issuer.pbData, cb->issuer.pbData, ca->issuer.cbData) == 0 && 
	       ca->serial.cbData == cb->serial.cbData && 
	       memcmp(ca->serial.pbData, cb->serial.pbData, ca->serial.cbData) == 0;
}

static void 
cert_object_release(void* data)
{
	CertObject* cobj = (CertObject*)data;
	ASSERT(cobj);
	free(cobj);
}

static const P11cObjectVtable cert_object_vtable = {
	cert_load_data,
	cert_hash_func,
	cert_equal_func,
	cert_object_release,
};

static CK_RV
calculate_check_value(PCCERT_CONTEXT cert, CK_ATTRIBUTE_PTR attr)
{
	BYTE* buffer;
	DWORD length;
	CK_RV ret;

	ASSERT(cert);
	ASSERT(attr);

	/* Short cut for the measuring case */
	if(!attr->pValue)
	{
		attr->ulValueLen = 3;
		return CKR_OK;
	}

	length = 0;
	if(!CryptHashCertificate(0, CALG_SHA1, 0, cert->pbCertEncoded, 
	                         cert->cbCertEncoded, NULL, &length))
		 return p11c_winerr_to_ckr(GetLastError());

	if(length < 3)
	{
		WARN(("SHA1 hash length too short: %d", length));
		return CKR_DEVICE_ERROR;
	}

	buffer = malloc(length);
	if(!buffer)
		return CKR_HOST_MEMORY;

	if(!CryptHashCertificate(0, CALG_SHA1, 0, cert->pbCertEncoded, 
	                         cert->cbCertEncoded, buffer, &length))
	{
		free(buffer);
		return p11c_winerr_to_ckr(GetLastError());
	}

	ret = p11c_return_data(attr, buffer, 3);
	free(buffer);
	return ret;
}


CK_RV 
p11c_cert_certificate_get_bytes(PCCERT_CONTEXT cert, CK_ATTRIBUTE_PTR attr)
{
	DWORD err;

	ASSERT(cert);
	ASSERT(attr);

	switch(attr->type)
	{

	/*
	 * Description of the object.
	 * - We use CAPI's CERT_FRIENDLY_NAME_PROP_ID property, 
	 *   converted into UTF8.
	 * - Yes this is slow, but this is not really a property
	 *   that's searched on or retrieved intensively.
	 */
	case CKA_LABEL:
		{
			WCHAR* utf16 = NULL;
			DWORD size;

			if(!CertGetCertificateContextProperty(cert, CERT_FRIENDLY_NAME_PROP_ID, NULL, &size))
			{
				err = GetLastError();
				if(err == CRYPT_E_NOT_FOUND)
					utf16 = L"Unnamed Certificate";
				else
					return p11c_winerr_to_ckr(err);
			}

			if(!utf16) 
			{
				utf16 = _alloca(size);
				if(!CertGetCertificateContextProperty(cert, CERT_FRIENDLY_NAME_PROP_ID, utf16, &size))
					return p11c_winerr_to_ckr(GetLastError());
			}

			return p11c_return_string(attr, utf16);
		}
		break;

	/*
	 * A byte array unique to this certificate. The CKA_ID of 
	 * matching certificates and private keys should match. 
	 * Should match the key identifier in an X.509v3 certificate.
	 * 
	 * We use CAPI's CERT_KEY_IDENTIFIER_PROP_ID property directly.
	 */
	case CKA_ID:
		if(!CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, 
		                                      attr->pValue, (DWORD*)&attr->ulValueLen))
		{
			err = GetLastError();
			if(err == CRYPT_E_NOT_FOUND)
				return CKR_ATTRIBUTE_TYPE_INVALID;
			return p11c_winerr_to_ckr(err);
		}
		return CKR_OK;
		

	/*
	 * DER-encoding of the certificate subject name.
	 * 
	 * We use CAPI's CERT_CONTEXT pCertInfo->Subject field
	 * directly. 
	 */
	case CKA_SUBJECT:
		return p11c_return_data(attr, cert->pCertInfo->Subject.pbData,
		                        cert->pCertInfo->Subject.cbData);

	/*
	 * DER-encoding of the certificate issuer name.
	 * 
	 * We use CAPI's CERT_CONTEXT pCertInfo->Issuer field
	 * directly.
	 */
	case CKA_ISSUER:
		return p11c_return_data(attr, cert->pCertInfo->Issuer.pbData,
		                        cert->pCertInfo->Issuer.cbData);

	/*
	 * DER-encoding of the certificate serial number.
	 */
	case CKA_SERIAL_NUMBER:
		if(!CryptEncodeObject(X509_ASN_ENCODING, X509_MULTI_BYTE_INTEGER,
		                      &cert->pCertInfo->SerialNumber, 
		                      attr->pValue, (DWORD*)&attr->ulValueLen))
		{
			err = GetLastError();
			if(err == ERROR_FILE_NOT_FOUND) {
                          p11c_log("ERROR_FILE_NOT_FOUND");
				return CKR_GENERAL_ERROR;
                        }
                        return p11c_winerr_to_ckr(err);
		}
		return CKR_OK;

	/*
	 * BER-encoding of the full certificate.
	 *
	 * We use CAPI's CERT_CONTEXT pbCertEncoded field directly.
	 */
	case CKA_VALUE:
		return p11c_return_data(attr, cert->pbCertEncoded,
		                        cert->cbCertEncoded);

	/*
	 * If CKA_VALUE not specified, this is where the full 
	 * certificate can be found. 
	 * 
	 * We don't support this. All our certificates are present
	 * in full.
	 * 
	 * - Spec says default to empty.
	 */
	case CKA_URL:
		return p11c_return_data(attr, "", 0);

	/*
	 * Checksum
	 * - This is the first 3 bytes of the SHA hash of the DER.
	 */
	case CKA_CHECK_VALUE:
		return calculate_check_value(cert, attr);

	/*
	 * Various hashes for remote retrieval.
	 * - Spec says default to empty.
	 */
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		return p11c_return_data(attr, "", 0);

	/*
	 * Start date for the certificate.
	 */
	case CKA_START_DATE:
		return p11c_return_filetime(attr, &cert->pCertInfo->NotBefore);

	/*
	 * End date for the certificate.
	 */
	case CKA_END_DATE:
		return p11c_return_filetime(attr, &cert->pCertInfo->NotAfter);

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
}

PCCERT_CONTEXT	
p11c_cert_object_data_get_certificate(P11cObjectData* objdata)
{
	CertObjectData* cdata;

	ASSERT(objdata);
	ASSERT(objdata->data_funcs == &cert_objdata_vtable);

	cdata = (CertObjectData*)objdata;
	return cdata->cert;
}

static CK_RV
register_cert_object(P11cSession* sess, PCCERT_CONTEXT cert, P11cObject** obj)
{
	CertObject* cobj;
	CK_RV ret;
	size_t len;

	/* We save the Issuer and SerialNumber for identification later */
	len = cert->pCertInfo->SerialNumber.cbData + 
		  cert->pCertInfo->Issuer.cbData;

	cobj = calloc(1, sizeof(CertObject) + len);
	if(!cobj)
		return CKR_HOST_MEMORY;

	cobj->obj.id = 0;
	cobj->obj.obj_funcs = &cert_object_vtable;

	/* Copy Issuer data in */
	cobj->issuer.cbData = cert->pCertInfo->Issuer.cbData;
	cobj->issuer.pbData = (BYTE*)(cobj + 1);
	memcpy(cobj->issuer.pbData, cert->pCertInfo->Issuer.pbData,
	       cobj->issuer.cbData);

	/* Copy Serial Number data in */
	cobj->serial.cbData = cert->pCertInfo->SerialNumber.cbData;
	cobj->serial.pbData = cobj->issuer.pbData + cobj->issuer.cbData;
	memcpy(cobj->serial.pbData, cert->pCertInfo->SerialNumber.pbData,
	       cobj->serial.cbData);
	
	ret = p11c_token_register_object(sess->slot, &(cobj->obj));
	if(ret != CKR_OK)
	{
		free(cobj);
		return ret;
	}

	ASSERT(cobj->obj.id != 0);
	*obj = &cobj->obj;
	return CKR_OK;
}

static CK_RV
find_in_store(P11cSession* sess, DWORD find_type, const void *find_criteria, 
              CK_ATTRIBUTE_PTR match, CK_ULONG count, P11cArray* arr)
{
	PCCERT_CONTEXT cert = NULL;
	P11cObject* obj;
	P11cObjectData* objdata;
	CertObjectData cdata;
	DWORD err;
	CK_RV ret = CKR_OK;

	/* No store, no objects */
	if(!sess->store)
		return CKR_OK;

	for(;;)
	{
		cert = CertFindCertificateInStore(sess->store, P11c_ENCODINGS, 0, 
		                                  find_type, find_criteria, cert);
		if(cert == NULL) 
		{
			err = GetLastError();

			/* Certificate not found, we don't care */
			if(err == CRYPT_E_NOT_FOUND)
				return CKR_OK;
			else
				return p11c_winerr_to_ckr(err);
		}

		/* Match the certificate */
		cdata.cert = cert;
		cdata.base.object = 0;
		cdata.base.data_funcs = &cert_objdata_vtable;

		if(p11c_object_data_match(&cdata.base, match, count))
		{
			ret = register_cert_object(sess, cert, &obj);
			if(ret == CKR_OK)
			{
				ASSERT(obj);

				/* Store away the object data for performance reasons */
				objdata = cert_alloc_data(sess, obj, cert);
				if(objdata)
				{
					p11c_session_take_object_data(sess, obj, objdata);

					/* For continuing the enumeration */
					cert = CertDuplicateCertificateContext(cert);
				}

				p11c_array_append(arr, obj->id);
			}
		}
	}

	if(ret != CKR_OK && cert)
		CertFreeCertificateContext(cert);

	return ret;
}

CK_RV
p11c_cert_find(P11cSession* sess, CK_OBJECT_CLASS cls, CK_ATTRIBUTE_PTR match, 
				 CK_ULONG count, P11cArray* arr)
{
	CRYPT_INTEGER_BLOB* serial = NULL; 
	CK_RV ret;
	CK_ULONG i;
	DWORD size;

	CERT_INFO find_info;       /* For searching by issuer and serial */
	CRYPT_HASH_BLOB find_key;  /* For searching by ID */

	/* We only have certificates here */
	if(cls != CKO_CERTIFICATE && cls != CKO_ANY)
		return CKR_OK;

	/* Only work with slots that have certificates */
	if(!(p11c_token_get_flags (sess->slot) & P11C_SLOT_CERTS))
		return CKR_OK;

	/* 
	 * There are some better searches we can do rather than 
	 * listing everything. 
	 * 
	 * CKA_ISSUER + CKA_SERIAL_NUMBER
	 * See if we have a issuer and serial number for a 
	 * specific certificate to find.
	 *
	 * CKA_ID
	 * Search by key identifier
	 * 
	 * TODO: could search by hash (use CertFindCertificateInStore 
	 * with CERT_FIND_HASH or CERT_FIND_SHA1_HASH or CERT_FIND_MD5_HASH)
	 * 
	 * TODO: could search by issuer (use CertFindCertificateInStore
	 * with CERT_FIND_ISSUER_NAME)
	 * 
	 * TODO: could search by subject (use CertFindCertificateInStore
	 * with CERT_FIND_SUBJECT_NAME)
	 * 
	 * TODO: could search by CKA_VALUE (use CertFindCertificateInStore
	 * with CERT_FIND_EXISTING)
	 */
	memset(&find_info, 0, sizeof(find_info));
	memset(&find_key, 0, sizeof(find_key));

	for(i = 0; i < count; ++i)
	{
		if(!match[i].pValue || !match[i].ulValueLen)
			continue;

		if(match[i].type == CKA_ISSUER)
		{
			find_info.Issuer.cbData = match[i].ulValueLen;
			find_info.Issuer.pbData = match[i].pValue;
		}

		else if(match[i].type == CKA_SERIAL_NUMBER && !serial)
		{
			if(!CryptDecodeObject(P11c_ENCODINGS, X509_MULTI_BYTE_INTEGER,
			                      match[i].pValue, match[i].ulValueLen, 0, NULL, &size))
			{
				continue;
			}

			serial = calloc(1, size);
			if(!serial)
				continue;

			if(!CryptDecodeObject(P11c_ENCODINGS, X509_MULTI_BYTE_INTEGER,
			                      match[i].pValue, match[i].ulValueLen, 0, serial, &size))
				continue;

			ASSERT(serial->cbData);
			ASSERT(serial->pbData);

			find_info.SerialNumber.cbData = serial->cbData;
			find_info.SerialNumber.pbData = serial->pbData;
		}

		else if(match[i].type == CKA_ID)
		{
			find_key.cbData = match[i].ulValueLen;
			find_key.pbData = match[i].pValue;
		}
	}

	/* Match a specific certificate */
	if(find_info.SerialNumber.cbData && find_info.Issuer.cbData) 
	{
		ret = find_in_store(sess, CERT_FIND_SUBJECT_CERT, &find_info, 
		                    match, count, arr);
	}

	/* Find all certificates with key identifier */
	else if(find_key.cbData)
	{
		ret = find_in_store(sess, CERT_FIND_KEY_IDENTIFIER, &find_key,
		                    match, count, arr);
	}

	/* Match any ol certificate */
	else 
	{
		ret = find_in_store(sess, CERT_FIND_ANY, NULL,
		                    match, count, arr);
	}

	if(serial)
		free(serial);

	return ret;
}

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
#include "p11-capi-trust.h"
#include "x509-usages.h"

#include "pkcs11/pkcs11n.h"

/* 
 * These are the attributes expected by NSS on a trust object:
 * 
 * CKA_CLASS
 * CKA_TOKEN
 * CKA_LABEL
 * CKA_CERT_SHA1_HASH
 * CKA_CERT_MD5_HASH
 * CKA_ISSUER
 * CKA_SUBJECT
 * CKA_TRUST_SERVER_AUTH
 * CKA_TRUST_CLIENT_AUTH
 * CKA_TRUST_EMAIL_PROTECTION
 * CKA_TRUST_CODE_SIGNING
 * CKA_SERIAL_NUMBER
 */

typedef struct _TrustObject
{
	P11cObject obj;
	CK_OBJECT_HANDLE cert_obj;
}
TrustObject;

typedef struct _TrustObjectData
{
	P11cObjectData base;

	PCCERT_CONTEXT cert;
	CERT_ENHKEY_USAGE* enhanced_usage;

	BOOL has_usage;
	BYTE usage;
}
TrustObjectData;

static CK_TRUST
has_usage(TrustObjectData* tdata, BYTE restriction)
{
	if(!tdata->has_usage)
		CKT_NETSCAPE_TRUST_UNKNOWN;
	if((tdata->usage & restriction) == restriction)
		return CKT_NETSCAPE_TRUSTED;
	return CKT_NETSCAPE_UNTRUSTED;

}

static CK_TRUST
has_enhanced_usage(TrustObjectData* tdata, const char* oid)
{
	CERT_ENHKEY_USAGE* eusage = tdata->enhanced_usage;
	DWORD i;

	/* No usages, means anything goes */
	if(eusage == NULL)
		return CKT_NETSCAPE_TRUSTED_DELEGATOR;

	for(i = 0; i < eusage->cUsageIdentifier; ++i)
	{
		if(eusage->rgpszUsageIdentifier[i] && 
		   strcmp(oid, eusage->rgpszUsageIdentifier[i]) == 0)
			return CKT_NETSCAPE_TRUSTED_DELEGATOR;
	}

	return CKT_NETSCAPE_TRUST_UNKNOWN;
}

static CK_RV
trust_bool_attribute(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr)
{
	CK_BBOOL val;

	ASSERT(objdata);
	ASSERT(attr);

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
	 */
	case CKA_MODIFIABLE:
		val = CK_TRUE;
		break;

	/* 
	 * TODO: Figure out what this is.
	 */
	case CKA_TRUST_STEP_UP_APPROVED:
		val = CK_FALSE;
		break;

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};

	return p11c_return_data(attr, &val, sizeof(CK_BBOOL));
}

static CK_RV
trust_ulong_attribute(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr)
{
	TrustObjectData* tdata = (TrustObjectData*)objdata;
	CK_ULONG val;

	ASSERT(tdata);
	ASSERT(attr);

	switch(attr->type)
	{

	/*
	 * Object class.
	 * - Always CKO_NETSCAPE_TRUST for netscape trust
	 */
	case CKA_CLASS:
		val = CKO_NETSCAPE_TRUST;
		break;

	/* 
	 * Key restrictions
	 */
	case CKA_TRUST_DIGITAL_SIGNATURE:
		val = has_usage(tdata, CERT_DIGITAL_SIGNATURE_KEY_USAGE);
		break;
	case CKA_TRUST_NON_REPUDIATION:
		val = has_usage(tdata, CERT_NON_REPUDIATION_KEY_USAGE);
		break;
	case CKA_TRUST_KEY_ENCIPHERMENT:
		val = has_usage(tdata, CERT_KEY_ENCIPHERMENT_KEY_USAGE);
		break;
	case CKA_TRUST_DATA_ENCIPHERMENT:
		val = has_usage(tdata, CERT_DATA_ENCIPHERMENT_KEY_USAGE);
		break;
	case CKA_TRUST_KEY_AGREEMENT:
		val = has_usage(tdata, CERT_KEY_AGREEMENT_KEY_USAGE);
		break;
	case CKA_TRUST_KEY_CERT_SIGN:
		val = has_usage(tdata, CERT_KEY_CERT_SIGN_KEY_USAGE);
		break;
	case CKA_TRUST_CRL_SIGN:
		val = has_usage(tdata, CERT_CRL_SIGN_KEY_USAGE);
		break;

	/* 
	 * Various trust flags 
	 */
	case CKA_TRUST_SERVER_AUTH:
		val = has_enhanced_usage(tdata, X509_USAGE_SERVER_AUTH);
		break;
	case CKA_TRUST_CLIENT_AUTH:
		val = has_enhanced_usage(tdata, X509_USAGE_CLIENT_AUTH);
		break;
	case CKA_TRUST_CODE_SIGNING:
		val = has_enhanced_usage(tdata, X509_USAGE_CODE_SIGNING);
		break;
	case CKA_TRUST_EMAIL_PROTECTION:
		val = has_enhanced_usage(tdata, X509_USAGE_EMAIL);
		break;
	case CKA_TRUST_IPSEC_END_SYSTEM:
		val = has_enhanced_usage(tdata, X509_USAGE_IPSEC_ENDPOINT);
		break;
	case CKA_TRUST_IPSEC_TUNNEL:
		val = has_enhanced_usage(tdata, X509_USAGE_IPSEC_TUNNEL);
		break;
	case CKA_TRUST_IPSEC_USER:
		val = has_enhanced_usage(tdata, X509_USAGE_IPSEC_USER);
		break;
	case CKA_TRUST_TIME_STAMPING:
		val = has_enhanced_usage(tdata, X509_USAGE_TIME_STAMPING);
		break;

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};

	return p11c_return_data(attr, &val, sizeof(CK_ULONG));
}

static CK_RV
trust_bytes_attribute(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr)
{
	TrustObjectData* tdata = (TrustObjectData*)objdata;

	ASSERT(tdata);
	ASSERT(attr);

	switch(attr->type)
	{
	/*
	 * Forward these through to the certificate itself.
	 */
	case CKA_SUBJECT:
	case CKA_ISSUER:
	case CKA_SERIAL_NUMBER:
	case CKA_LABEL:
		ASSERT(tdata->cert);
		return p11c_cert_certificate_get_bytes(tdata->cert, attr);

	/* 
	 * The hash of the DER encoded certificate.
	 */
	case CKA_CERT_MD5_HASH:
	case CKA_CERT_SHA1_HASH:
		if(!CryptHashCertificate(0, attr->type == CKA_CERT_MD5_HASH ? CALG_MD5 : CALG_SHA1,
		                         0, tdata->cert->pbCertEncoded, 
		                         tdata->cert->cbCertEncoded, attr->pValue, 
		                         (DWORD*)(&attr->ulValueLen)))
			return p11c_winerr_to_ckr(GetLastError());
		return CKR_OK;
	};

	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static unsigned int
trust_hash_func(P11cObject* obj)
{
	return p11c_hash_integer(((TrustObject*)obj)->cert_obj);
}

static int
trust_equal_func(P11cObject* a, P11cObject* b)
{
	return ((TrustObject*)a)->cert_obj == ((TrustObject*)b)->cert_obj;
}

static void
trust_release(void* data)
{
	TrustObjectData* tdata = (TrustObjectData*)data;
	ASSERT(tdata);

	ASSERT(tdata->cert);
	CertFreeCertificateContext(tdata->cert);

	if(tdata->enhanced_usage)
		free(tdata->enhanced_usage);

	free(tdata);
}

static const P11cObjectDataVtable trust_objdata_vtable = {
	trust_bool_attribute,
	trust_ulong_attribute,
	trust_bytes_attribute,
	trust_release,
};

static CK_RV
parse_usage(TrustObjectData* tdata, DWORD flags)
{
	DWORD size, err;
	CERT_ENHKEY_USAGE* eusage;

	ASSERT(!tdata->enhanced_usage);

	/* Get the size of the enhanced_usage */
	if(!CertGetEnhancedKeyUsage(tdata->cert, flags, NULL, &size))
	{
		err = GetLastError();

		/* No enhanced_usage data is not an error */
		if(err == CRYPT_E_NOT_FOUND)
			return CKR_OK; 
		return p11c_winerr_to_ckr(err);
	}

	eusage = (CERT_ENHKEY_USAGE*)calloc(1, size);
	if(!eusage)
		return CKR_HOST_MEMORY;

	/* Now get the actual enhanced usage property */
	if(!CertGetEnhancedKeyUsage(tdata->cert, flags, eusage, &size))
	{
		err = GetLastError();
		if(err == CRYPT_E_NOT_FOUND)
			return CKR_OK;
		return p11c_winerr_to_ckr(err);
	}

	tdata->enhanced_usage = eusage;
	return CKR_OK;
}

static CK_RV
parse_restrictions(TrustObjectData* tdata)
{
	CRYPT_BIT_BLOB* rst;
	CERT_EXTENSION* ext;
	DWORD size;

	ASSERT(tdata);
	ASSERT(tdata->cert);

	tdata->has_usage = CK_FALSE;
	tdata->usage = 0x00;

	ext = CertFindExtension(szOID_KEY_USAGE, 
	                        tdata->cert->pCertInfo->cExtension,
	                        tdata->cert->pCertInfo->rgExtension);

	/* No key usage, don't care */
	if(!ext)
		return CKR_OK;

	/* Find the size of the decoded structure */
	if(!CryptDecodeObject(P11c_ENCODINGS, X509_KEY_USAGE, 
	                      ext->Value.pbData, ext->Value.cbData, 0, NULL, &size))
		return p11c_winerr_to_ckr(GetLastError());

	/* Allocate enough memory */
	rst = (CRYPT_BIT_BLOB*)calloc(1, size);
	if(!rst)
		return CKR_HOST_MEMORY;

	/* And get the decoded structure */
	if(CryptDecodeObject(P11c_ENCODINGS, X509_KEY_USAGE, 
	                     ext->Value.pbData, ext->Value.cbData, 0, rst, &size))
	{
		if(rst->cbData != 1 && 
		   rst->cUnusedBits != 0)
		{
			WARN(("key usage are of invalid size"));
		}
		else
		{
			/* A valid byte of key restricted usage flags. Yes all that for one byte */
			tdata->usage = *((BYTE*)(rst->pbData));
			tdata->has_usage = TRUE;
		}
	}

	free(rst);
	return CKR_OK;
}

static CK_RV 
trust_load_data(P11cSession* sess, P11cObject* obj, P11cObjectData** objdata)
{
	TrustObject* tobj = (TrustObject*)obj;
	TrustObjectData* tdata;
	P11cObjectData* certdata;
	CK_RV ret;

	ASSERT(tobj);
	ASSERT(objdata);

	/* Get the raw data for the certificate */
	ret = p11c_session_get_object_data_for(sess, tobj->cert_obj, &certdata);
	if(ret != CKR_OK)
		return ret;

	tdata = (TrustObjectData*)calloc(1, sizeof(TrustObjectData));
	if(!tdata)
		return CKR_HOST_MEMORY;

	tdata->cert = p11c_cert_object_data_get_certificate (certdata);
	ASSERT(tdata->cert);

	/* Dig up the restrictions data extension */
	ret = parse_restrictions(tdata);
	if(ret != CKR_OK)
	{
		free(tdata);
		return ret;
	}

	/* Dig up the enhanced usage data property, and then try the extension */
	ret = parse_usage(tdata, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG);
	if(ret == CKR_OK && !tdata->enhanced_usage)
		ret = parse_usage(tdata, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG);

	if(ret != CKR_OK)
	{
		free(tdata);
		return ret;
	}

	/* And keep a reference to the certificate */
	tdata->cert = CertDuplicateCertificateContext(tdata->cert);

	tdata->base.object = obj->id;
	tdata->base.data_funcs = &trust_objdata_vtable;

	*objdata = &(tdata->base);
	return CKR_OK;
}


static void 
trust_object_release(void* data)
{
	TrustObject* tobj = (TrustObject*)data;
	ASSERT(tobj);
	free(tobj);
}

static const P11cObjectVtable trust_object_vtable = {
	trust_load_data,
	trust_hash_func,
	trust_equal_func,
	trust_object_release,
};

static CK_RV
register_trust_object(P11cSession* sess, P11cObject* cert, P11cObject** obj)
{
	TrustObject* tobj;
	CK_RV ret;

	tobj = calloc(1, sizeof(TrustObject));
	if(!tobj)
		return CKR_HOST_MEMORY;

	tobj->cert_obj = cert->id;

	tobj->obj.id = 0;
	tobj->obj.obj_funcs = &trust_object_vtable;

	ret = p11c_token_register_object(sess->slot, &(tobj->obj));
	if(ret != CKR_OK)
	{
		free(tobj);
		return ret;
	}

	ASSERT(tobj->obj.id != 0);
	*obj = &(tobj->obj);

	return CKR_OK;
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
		 * These are the attributes that tie a certificate 
		 * to trust object, so try match certs with these
		 */
		if(match[i].type == CKA_ISSUER || 
		   match[i].type == CKA_SERIAL_NUMBER)
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

CK_RV
p11c_trust_find(P11cSession* sess, CK_OBJECT_CLASS cls, 
				  CK_ATTRIBUTE_PTR match, CK_ULONG count, P11cArray* arr)
{
	CK_OBJECT_HANDLE id;
	P11cObject* obj;
	P11cObject* certobj;
	P11cObjectData* objdata;
	P11cArray* certarr;
	CK_RV ret = CKR_OK;
	CK_ULONG i;

	/* We only have trust objects in here */
	if(cls != CKO_NETSCAPE_TRUST && cls != CKO_ANY)
		return CKR_OK;

	/* Only work with slots that have certificates */
	if(!(p11c_token_get_flags (sess->slot) & P11C_SLOT_CERTS))
		return CKR_OK;

	/* Get a list of all certificates */
	certarr = p11c_array_new(0, 1, sizeof(CK_OBJECT_HANDLE));
	if(!certarr)
		return CKR_HOST_MEMORY;
	ret = list_matching_certificates(sess, match, count, certarr);

	/* Now match each of them against our criteria */
	if(ret == CKR_OK)
	{
		for(i = 0; i < certarr->len; ++i)
		{
			id = p11c_array_index(certarr, CK_OBJECT_HANDLE, i);
			ASSERT(id);

			certobj = p11c_token_lookup_object(sess->slot, id);
			ASSERT(certobj);

			/* We'll register a trust object for any loaded certificate */
			ret = register_trust_object(sess, certobj, &obj);
			if(ret != CKR_OK)
				break;

			ASSERT(obj);

			ret = p11c_session_get_object_data(sess, obj, &objdata);
			if(ret != CKR_OK)
				break;

			/* Only return new object if it matches */
			if(p11c_object_data_match(objdata, match, count))
				p11c_array_append(arr, obj->id);
		}
	}

	p11c_array_free(certarr, TRUE);
	return ret;
}

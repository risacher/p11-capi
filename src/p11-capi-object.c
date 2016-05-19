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
#include "p11-capi-object.h"

#include "pkcs11/pkcs11n.h"

#include <memory.h>

enum 
{
	DATA_UNKNOWN = 0,
	DATA_BOOL,
	DATA_ULONG,
	DATA_BYTES
};

int
attribute_data_type(CK_ATTRIBUTE_TYPE type)
{
	switch(type)
	{
	// CK_ULONG attribute types
	case CKA_CLASS:
	case CKA_CERTIFICATE_TYPE:
	case CKA_CERTIFICATE_CATEGORY:
	case CKA_KEY_TYPE:
	case CKA_MODULUS_BITS:
	case CKA_PRIME_BITS:
	/* case CKA_SUBPRIME_BITS: */
	case CKA_SUB_PRIME_BITS: 
	case CKA_VALUE_BITS:
	case CKA_VALUE_LEN:
	case CKA_KEY_GEN_MECHANISM:
	case CKA_HW_FEATURE_TYPE:
	case CKA_PIXEL_X:
	case CKA_PIXEL_Y:
	case CKA_RESOLUTION:
	case CKA_CHAR_ROWS:
	case CKA_CHAR_COLUMNS:
	case CKA_BITS_PER_PIXEL:
	case CKA_MECHANISM_TYPE:
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
	case CKA_TRUST_SERVER_AUTH:
	case CKA_TRUST_CLIENT_AUTH:
	case CKA_TRUST_CODE_SIGNING:
	case CKA_TRUST_EMAIL_PROTECTION:
	case CKA_TRUST_IPSEC_END_SYSTEM:
	case CKA_TRUST_IPSEC_TUNNEL:
	case CKA_TRUST_IPSEC_USER:
	case CKA_TRUST_TIME_STAMPING:
		return DATA_ULONG;

	// CK_BBOOL attribute types
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
	case CKA_TRUSTED:
	case CKA_SENSITIVE:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_UNWRAP:
	case CKA_EXTRACTABLE:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_WRAP_WITH_TRUSTED:
	case CKA_ALWAYS_AUTHENTICATE:
	case CKA_ENCRYPT:
	case CKA_WRAP:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_DERIVE:
	case CKA_LOCAL:
	case CKA_RESET_ON_INIT:
	case CKA_HAS_RESET:
	case CKA_COLOR:
	case CKA_TRUST_STEP_UP_APPROVED:
		return DATA_BOOL;

	// Raw or string data
	case CKA_LABEL:
	case CKA_APPLICATION:
	case CKA_VALUE:
	case CKA_OBJECT_ID:
	case CKA_CHECK_VALUE:
	case CKA_ISSUER:
	case CKA_SERIAL_NUMBER:
	case CKA_SUBJECT:
	case CKA_ID:
	case CKA_URL:
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
	case CKA_AC_ISSUER:
	case CKA_OWNER:
	case CKA_ATTR_TYPES:
	case CKA_MODULUS:
	case CKA_PUBLIC_EXPONENT:
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
	case CKA_PRIME:
	case CKA_SUBPRIME:
	case CKA_BASE:
	case CKA_ECDSA_PARAMS:
	/* case CKA_EC_PARAMS: */
	case CKA_EC_POINT:
	case CKA_CHAR_SETS:
	case CKA_ENCODING_METHODS:
	case CKA_MIME_TYPES:
	case CKA_REQUIRED_CMS_ATTRIBUTES:
	case CKA_DEFAULT_CMS_ATTRIBUTES:
	case CKA_SUPPORTED_CMS_ATTRIBUTES:
	case CKA_CERT_SHA1_HASH:
	case CKA_CERT_MD5_HASH:
	case CKA_ALLOWED_MECHANISMS:
	case CKA_START_DATE:
	case CKA_END_DATE:
		return DATA_BYTES;

	// Arrays are nasty
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	default:
		WARN(("unknown attribute type: %x", type));
		return DATA_UNKNOWN;
	};
}

CK_BBOOL
p11c_object_data_match_attr(P11cObjectData* objdata, CK_ATTRIBUTE_PTR match)
{
	CK_ATTRIBUTE attr;
	CK_RV rv;
	int dtype;

	ASSERT(match);
	ASSERT(objdata);
	ASSERT(objdata->data_funcs);

	/* Get the data type of the attribute */
	dtype = attribute_data_type(match->type);
	if(dtype == DATA_UNKNOWN)
		return CK_FALSE;

	/* We only do byte matching */
	if(match->pValue == NULL)
		return CK_FALSE;

	/* Only load as much data as is needed */
	attr.type = match->type;
	attr.pValue = _alloca(match->ulValueLen > 4 ? match->ulValueLen : 4);
	attr.ulValueLen = match->ulValueLen;

	switch(dtype)
	{
	case DATA_BOOL:
		rv = (objdata->data_funcs->get_bool)(objdata, &attr);
		break;
	case DATA_ULONG:
		rv = (objdata->data_funcs->get_ulong)(objdata, &attr);
		break;
	case DATA_BYTES:
		rv = (objdata->data_funcs->get_bytes)(objdata, &attr);
		break;
	default:
		ASSERT(0 && "unrecognized type");
		break;
	};

	/* Unrecognized attribute */
	if(rv == CKR_ATTRIBUTE_TYPE_INVALID)
		return CK_FALSE;

	/* Value is longer than this one */
	if(rv == CKR_BUFFER_TOO_SMALL)
		return CK_FALSE;

	/* All other errors */
	if(rv != CKR_OK)
		return CK_FALSE;

	return (match->ulValueLen == attr.ulValueLen &&
	        memcmp(match->pValue, attr.pValue, attr.ulValueLen) == 0);
}

CK_BBOOL
p11c_object_data_match(P11cObjectData* objdata, CK_ATTRIBUTE_PTR matches, 
						 CK_ULONG count)
{
	CK_ULONG i;

	for(i = 0; i < count; ++i)
	{
		if(!p11c_object_data_match_attr(objdata, &matches[i]))
			return CK_FALSE;
	}

	return CK_TRUE;
}

CK_RV
p11c_object_data_get_attrs(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attrs, 
							 CK_ULONG count)
{
	CK_ULONG i;
	CK_RV rv, ret = CKR_OK;

	ASSERT(objdata);
	ASSERT(!count || attrs);

	for(i = 0; i < count; ++i)
	{
		/* Get the data type of the attribute */
		switch(attribute_data_type(attrs[i].type))
		{
		case DATA_BOOL:
			rv = (objdata->data_funcs->get_bool)(objdata, &attrs[i]);
			break;
		case DATA_ULONG:
			rv = (objdata->data_funcs->get_ulong)(objdata, &attrs[i]);
			break;
		case DATA_BYTES:
			rv = (objdata->data_funcs->get_bytes)(objdata, &attrs[i]);
			break;
		case DATA_UNKNOWN:
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		default:
			ASSERT(0 && "unrecognized type");
			break;
		};

		/* Not an error if they were just requesting the size */
		if(rv != CKR_OK)
		{
			if(rv == CKR_BUFFER_TOO_SMALL)
			{
				if(!attrs[i].pValue)
					rv = CKR_OK;
			}

			/* Attribute is sensitive */
			else if(rv == CKR_ATTRIBUTE_SENSITIVE)
			{
				attrs[i].ulValueLen = (CK_ULONG)-1;
			}

			/* Attribute doesn't exist */
			else if(rv == CKR_ATTRIBUTE_TYPE_INVALID)
			{
				WARN(("O%d: attribute not found: 0x%08x", objdata->object, attrs[i].type));
				attrs[i].ulValueLen = (CK_ULONG)-1;
			}

			/* A fatal error? */
			else
			{
				ret = rv;
				break;
			}

			/* Transfer any non-fatal errors outward */
			if(rv != CKR_OK && ret == CKR_OK)
				ret = rv;
		}
	}

	return ret;
}

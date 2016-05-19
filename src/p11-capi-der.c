/* 
 * Portions derived from NSS source files: 
 *     lib/ckfw/capi/cobject.c
 *     lib/ckfw/capi/crsa.c
 *
 * Portions of this file:
 *     Copyright (C) Stef Walter 2008
 * 
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
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 * Portions created by Red Hat, Inc, are Copyright (C) 2005
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

#include "p11-capi.h"
#include "p11-capi-der.h"

/*
 * unwrap a single DER value
 */
BYTE*
p11c_der_unwrap(BYTE* src, DWORD n_src, 
                DWORD* n_result, BYTE** next)
{
	BYTE* start = src;
	BYTE* end = src + n_src;
	DWORD len = 0;

	/* initialize error condition return values */
	*n_result = 0;
	if(next)
		*next = src;

	if(n_src < 2)
		return start;

	src++ ; /* skip the tag -- should check it against an expected value! */
	len = (DWORD)*src++;
	if(len & 0x80) 
	{
		DWORD count = len & 0x7f;
		len = 0;

		if(count + 2 > n_src) 
			return start;

		while(count-- > 0)
			len = (len << 8) | (DWORD)*src++;
	}

	if(len + (src - start) > (DWORD)n_src)
		return start;

	if(next)
		*next = src + len;

	*n_result = len;
	return src;
}

/*
 * write a Decimal value to a string
 */

static char*
put_decimal_string(char* cstr, DWORD value)
{
	DWORD tenpower;
	BOOL first = TRUE;

	for(tenpower = 10000000; tenpower; tenpower /= 10) 
	{
		BYTE digit = (BYTE)(value / tenpower);
		value = value % tenpower;

		/* drop leading zeros */
		if(first && (0 == digit))
			continue;

		first = FALSE;
		*cstr++ = digit + '0';
	}

	/* if value was zero, put one of them out */
	if(first)
		*cstr++ = '0';

	return cstr;
}

/*
 * Create a Capi OID string value from a DER OID
 */
char*
p11c_der_read_oid(BYTE* oid_tag, DWORD n_oid_tag)
{
	BYTE* oid;
	char *oid_str;
	char *cstr;
	DWORD value;
	DWORD n_oid;

	/* wasn't an oid */
	if(P11C_DER_OBJECT_ID != *oid_tag) 
		return NULL;

	oid = p11c_der_unwrap(oid_tag, n_oid_tag, &n_oid, NULL);;
	if(n_oid < 2) 
		return NULL;

	oid_str = malloc(n_oid * 4);
	if(!oid_str) 
		return NULL;

	cstr = oid_str;
	cstr = put_decimal_string(cstr, (*oid) / 40);
	*cstr++ = '.';
	cstr = put_decimal_string(cstr, (*oid) % 40);
	n_oid--;

	value = 0;
	while(n_oid--) 
	{
		oid++;
		value = (value << 7) + (*oid & 0x7f);
		if(0 == (*oid & 0x80)) 
		{
			*cstr++ = '.';
			cstr = put_decimal_string(cstr, value);
			value = 0;
		}
	}

	*cstr = 0; /* NULL terminate */

	if(value != 0) 
	{
		free(oid_str);
		return NULL;
	}

	return oid_str;
}

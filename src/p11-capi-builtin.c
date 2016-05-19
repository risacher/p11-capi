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
#include "p11-capi-session.h"
#include "p11-capi-token.h"

#include "pkcs11/pkcs11n.h"

/* --------------------------------------------------------------------------
 * BUILT IN VALUES 
 */

static const CK_BBOOL ck_true = CK_TRUE;
static const CK_BBOOL ck_false = CK_FALSE;

static const CK_OBJECT_CLASS cko_sample_class = CKO_DATA;

static const char ck_sample_label[] = "Sample Builtin";

/* --------------------------------------------------------------------------
 * BUILT IN OBJECTS
 */

#define CK_END_LIST (CK_ULONG)-1

static const CK_ATTRIBUTE builtin_sample[] = {
	{ CKA_TOKEN, (void*)&ck_true, sizeof(CK_BBOOL) },
	{ CKA_PRIVATE, (void*)&ck_false, sizeof(CK_BBOOL) },
	{ CKA_LABEL, (void*)ck_sample_label, sizeof(ck_sample_label) },
	{ CK_END_LIST, NULL, 0 }
};

typedef struct _BuiltinMatch
{
	CK_ATTRIBUTE_PTR attr;
	CK_ULONG slot_flags;
}
BuiltinMatch;

static const BuiltinMatch all_builtins[] = {
	{ (CK_ATTRIBUTE_PTR)&builtin_sample, P11C_SLOT_CERTS },
	{ NULL, 0 }
};

/* This is filled in later */
static CK_ULONG num_builtins = CK_END_LIST;

/* --------------------------------------------------------------------------
 * IMPLEMENTATION
 */

/* Represents a loaded builtin object */
typedef struct _BuiltinObject
{
	P11cObject obj;
	CK_ATTRIBUTE_PTR attr;
}
BuiltinObject;

typedef struct _BuiltinObjectData
{
	P11cObjectData base;
	CK_ATTRIBUTE_PTR attr;
}
BuiltinObjectData;

static CK_RV
builtin_attribute(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr)
{
	BuiltinObjectData* bdata = (BuiltinObjectData*)objdata;
	CK_ATTRIBUTE_PTR builtin = bdata->attr;

	ASSERT(attr);
	ASSERT(bdata);

	while(builtin->type != CK_END_LIST)
	{
		if(builtin->type == attr->type)
		{
			if(builtin->ulValueLen == 0)
				return CKR_ATTRIBUTE_TYPE_INVALID;
			return p11c_return_data(attr, builtin->pValue, builtin->ulValueLen);
		}

		builtin++;
	}

	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static void
builtin_data_release(void* data)
{
	BuiltinObjectData* bdata = (BuiltinObjectData*)data;
	ASSERT(bdata);
	free(bdata);
}

static const P11cObjectDataVtable builtin_objdata_vtable = {
	builtin_attribute,
	builtin_attribute,
	builtin_attribute,
	builtin_data_release,
};

static CK_RV 
builtin_load_data(P11cSession* sess, P11cObject* obj, P11cObjectData** objdata)
{
	BuiltinObject* bobj = (BuiltinObject*)obj;
	BuiltinObjectData* bdata;

	ASSERT(bobj);
	ASSERT(objdata);
	ASSERT(num_builtins != CK_END_LIST);

	bdata = (BuiltinObjectData*)calloc(1, sizeof(BuiltinObjectData));
	if(!bdata)
		return CKR_HOST_MEMORY;

	/* Simple, just use same data */
	bdata->attr = bobj->attr;

	bdata->base.object = obj->id;
	bdata->base.data_funcs = &builtin_objdata_vtable;

	*objdata = &(bdata->base);
	return CKR_OK;
}

static unsigned int
builtin_hash_func(P11cObject* obj)
{
	return p11c_hash_pointer(((BuiltinObject*)obj)->attr);
}

static int
builtin_equal_func(P11cObject* one, P11cObject* two)
{
	return ((BuiltinObject*)one)->attr == ((BuiltinObject*)two)->attr;
}

static void 
builtin_object_release(void* data)
{
	BuiltinObject* bobj = (BuiltinObject*)data;
	ASSERT(bobj);
	free(bobj);
}

static const P11cObjectVtable builtin_object_vtable = {
	builtin_load_data,
	builtin_hash_func,
	builtin_equal_func,
	builtin_object_release,
};

static CK_RV
register_builtin_object(P11cSession* sess, CK_ATTRIBUTE_PTR attr, P11cObject** obj)
{
	BuiltinObject* bobj;
	CK_RV ret;

	bobj = calloc(1, sizeof(BuiltinObject));
	if(!bobj)
		return CKR_HOST_MEMORY;

	bobj->attr = attr;

	bobj->obj.id = 0;
	bobj->obj.obj_funcs = &builtin_object_vtable;

	ret = p11c_token_register_object(sess->slot, &(bobj->obj));
	if(ret != CKR_OK)
	{
		free(bobj);
		return ret;
	}

	ASSERT(bobj->obj.id != 0);
	*obj = &(bobj->obj);
	return CKR_OK;
}

CK_RV
p11c_builtin_find(P11cSession* sess, CK_OBJECT_CLASS cls, CK_ATTRIBUTE_PTR match, 
					CK_ULONG count, P11cArray* arr)
{
	P11cObject* obj;
	BuiltinObjectData bdata;
	CK_RV ret = CKR_OK;
	CK_ULONG i, fl;

	/* First time around count total number */
	if(num_builtins == CK_END_LIST)
	{
		num_builtins = 0;
		while(all_builtins[num_builtins].attr)
			++num_builtins;
	}

	/* Match each certificate */
	for(i = 0; i < num_builtins; ++i)
	{
		/* Only apply built in objects to appropriate slots */
		fl = p11c_token_get_flags(sess->slot) & all_builtins[i].slot_flags;
		if(fl != all_builtins[i].slot_flags)
			continue;
	
		bdata.attr = all_builtins[i].attr;
		bdata.base.object = 0;
		bdata.base.data_funcs = &builtin_objdata_vtable;

		if(p11c_object_data_match(&bdata.base, match, count))
		{
			ret = register_builtin_object(sess, all_builtins[i].attr, &obj);
			if(ret != CKR_OK)
				break;

			p11c_array_append(arr, obj->id);
		}
	}

	return ret;
}


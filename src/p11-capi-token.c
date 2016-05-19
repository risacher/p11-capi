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
#include "p11-capi-token.h"

static P11cArray* object_array = NULL;
static P11cHash* object_hash = NULL;
static P11cArray* logged_in_slots = NULL;

typedef struct _SlotInfo
{
	const char* capi_store;
	const char* display_name;
	CK_ULONG slot_flags;
}
SlotInfo;

#define SLOT_OFFSET  0x00001000

static SlotInfo slot_info[] = {
	{ "My", "Personal Certificates", P11C_SLOT_TRUSTED | P11C_SLOT_CERTS },
	{ "AddressBook", "Address Book Certificates", P11C_SLOT_CERTS },
	{ "CA", "Certificate Authorities", P11C_SLOT_CA | P11C_SLOT_CERTS },  
	{ "Root", "Root Authorities", P11C_SLOT_TRUSTED | P11C_SLOT_CA | P11C_SLOT_CERTS }, 
	{ "Trust", "Trust", P11C_SLOT_CERTS }, 
	{ "TrustedPeople", "Trusted People", P11C_SLOT_TRUSTED | P11C_SLOT_CERTS }, 
	{ "AuthRoot", "Auth Root", P11C_SLOT_CERTS },
	{ NULL, "All User Keys", P11C_SLOT_ANYKEY }
};

#define SLOT_TO_OFFSET(slot) \
	((slot) & ~(SLOT_OFFSET))

#define OFFSET_TO_SLOT(offset) \
	((offset) | SLOT_OFFSET)

unsigned int 
p11c_token_get_count(void)
{
	return sizeof(slot_info) / sizeof(slot_info[0]);
}

CK_SLOT_ID
p11c_token_get_slot_id(unsigned int offset)
{
	ASSERT(offset < p11c_token_get_count());
	return OFFSET_TO_SLOT(offset);
}

CK_BBOOL
p11c_token_is_valid(CK_SLOT_ID slot)
{
	unsigned int offset = SLOT_TO_OFFSET(slot);
	return offset >= 0 && offset < p11c_token_get_count();
}

const char*
p11c_token_get_display_name(CK_SLOT_ID slot)
{
	unsigned int offset = SLOT_TO_OFFSET(slot);
	ASSERT(p11c_token_is_valid(slot));
	ASSERT(slot_info[offset].display_name); 
	return slot_info[offset].display_name;
}

const char*
p11c_token_get_store_name(CK_SLOT_ID slot)
{
	unsigned int offset = SLOT_TO_OFFSET(slot);
	ASSERT(p11c_token_is_valid(slot));
	return slot_info[offset].capi_store;
}

CK_ULONG
p11c_token_get_flags(CK_SLOT_ID slot)
{
	unsigned int offset = SLOT_TO_OFFSET(slot);
	ASSERT(p11c_token_is_valid(slot));
	return slot_info[offset].slot_flags;
}

static void 
object_free(P11cObject* obj)
{
	ASSERT(obj);
	ASSERT(obj->obj_funcs);
	ASSERT(obj->obj_funcs->release);
	(obj->obj_funcs->release)(obj);
}

void
p11c_token_cleanup_all(void)
{
	size_t i;

	p11c_lock_global();

		if(object_hash)
		{
			p11c_hash_free(object_hash, NULL);
			object_hash = NULL;
		}

		if(object_array)
		{
			for(i = 1; i < object_array->len; ++i)
			{
				ASSERT(p11c_array_index(object_array, P11cObject*, i));
				object_free(p11c_array_index(object_array, P11cObject*, i));
			}

			p11c_array_free(object_array, TRUE);
			object_array = NULL;
		}

		if(logged_in_slots)
		{
			p11c_array_free(logged_in_slots, TRUE);
			logged_in_slots = NULL;
		}

	p11c_unlock_global();
}

CK_OBJECT_HANDLE
p11c_token_get_max_handle(void)
{
	if(!object_array)
		return 0;
	return object_array->len;
}

P11cObject*
p11c_token_lookup_object(CK_SLOT_ID slot, CK_OBJECT_HANDLE obj)
{
	/* This must be called without any locks held */

	P11cObject* ret = NULL;

	ASSERT(slot);
	ASSERT(obj > 0);
	
	p11c_lock_global();
	
		if(object_array && obj < object_array->len)
			ret = p11c_array_index(object_array, P11cObject*, obj);

	p11c_unlock_global();

	/* Must belong to the right slot */
	if(ret && ret->slot != slot)
		ret = NULL;

	return ret;
}

static unsigned int
object_hash_func(const void* a)
{
	P11cObject* obj = (P11cObject*)a;
	unsigned int hash = p11c_hash_pointer(obj->obj_funcs);
	hash ^= p11c_hash_integer((int)obj->slot);
	hash ^= (obj->obj_funcs->hash_object)(obj);
	return hash;
}

static int
object_equal_func(const void* a, const void* b)
{
	P11cObject* ca = (P11cObject*)a;
	P11cObject* cb = (P11cObject*)b;
	if(ca == cb)
		return 1;
	if(ca->slot != cb->slot)
		return 0;
	if(ca->obj_funcs != cb->obj_funcs)
		return 0;
	return (ca->obj_funcs->equal_object)(ca, cb);
}

CK_RV
p11c_token_register_object(CK_SLOT_ID slot, P11cObject* obj)
{
	P11cObject* prev;
	CK_RV ret = CKR_OK;

	ASSERT(slot);
	ASSERT(obj->id == 0);

	DBG(("registering object"));

	p11c_lock_global();

		if(!object_array)
		{
			object_array = p11c_array_sized_new(0, 1, sizeof(P11cObject*), 16);
			if(object_array) 
			{
				/* A blank entry for '0' */
				P11cObject* blank = NULL;
				p11c_array_append(object_array, blank);
			}

			object_hash = p11c_hash_new(object_hash_func, object_equal_func);

			if(!object_array || !object_hash)
			{
				/* Allocation failed above */
				ret = CKR_HOST_MEMORY;
			}
		}

		if(ret == CKR_OK)
		{
			ASSERT(object_array);
			ASSERT(object_hash);

			/* Look in the hash and find a previous object */
			prev = p11c_hash_get(object_hash, obj);
			if(prev)
			{
				/* Register it in the previous object's place */
				obj->id = prev->id;
				ASSERT(prev->id < object_array->len);
				if(p11c_hash_set(object_hash, obj, obj))
				{
					p11c_array_index(object_array, P11cObject*, obj->id) = obj;
					object_free(prev);
					DBGO(obj, "found old object id");
				}
				else
				{
					ret = CKR_HOST_MEMORY;
				}
			}
			else
			{
				/* Register it at the end of the array */
				obj->id = object_array->len;
				ASSERT(obj->id > 0);
				if(p11c_hash_set(object_hash, obj, obj))
				{
					if(p11c_array_append(object_array, obj))
					{
						DBGO(obj, "registered new object id");
					}
					else
					{
						ret = CKR_HOST_MEMORY;

						/* Roll back our addition */
						p11c_hash_rem(object_hash, obj);
					}
				}
				else
				{
					ret = CKR_HOST_MEMORY;
				}
			}
		}

		if(ret == CKR_OK)
			obj->slot = slot;

	p11c_unlock_global();

	return ret;

}

CK_BBOOL
p11c_token_is_logged_in(CK_SLOT_ID slot)
{
	unsigned int count, offset;

	ASSERT(p11c_token_is_valid(slot));

	if(!logged_in_slots)
		return CK_FALSE;

	offset = SLOT_TO_OFFSET(slot);
	count = p11c_token_get_count();

	ASSERT(logged_in_slots->len == count && offset < count);
	return p11c_array_index(logged_in_slots, CK_BBOOL, offset);
}

CK_RV
p11c_token_login(CK_SLOT_ID slot)
{
	unsigned int i, count;
	unsigned int offset;
	CK_BBOOL value;

	ASSERT(p11c_token_is_valid(slot));

	offset = SLOT_TO_OFFSET(slot);
	count = p11c_token_get_count();

	if(!logged_in_slots)
	{
		logged_in_slots = p11c_array_sized_new(0, 1, sizeof(CK_BBOOL), count);
		if(!logged_in_slots)
			return CKR_HOST_MEMORY;

		value = CK_FALSE;
		for(i = 0; i < count; ++i)
			p11c_array_append(logged_in_slots, value);

	}

	ASSERT(logged_in_slots->len == count && offset < count);
	if(p11c_array_index(logged_in_slots, CK_BBOOL, offset))
		return CKR_USER_ALREADY_LOGGED_IN;

	p11c_array_index(logged_in_slots, CK_BBOOL, offset) = CK_TRUE;
	return CKR_OK;
}

CK_RV
p11c_token_logout(CK_SLOT_ID slot)
{
	unsigned int count, offset;

	ASSERT(p11c_token_is_valid(slot));

	if(!logged_in_slots)
		return CKR_USER_NOT_LOGGED_IN;

	offset = SLOT_TO_OFFSET(slot);
	count = p11c_token_get_count();

	ASSERT(logged_in_slots->len == count && offset < count);
	if(!p11c_array_index(logged_in_slots, CK_BBOOL, offset))
		return CKR_USER_NOT_LOGGED_IN;

	p11c_array_index(logged_in_slots, CK_BBOOL, offset) = CK_FALSE;
	return CKR_OK;
}

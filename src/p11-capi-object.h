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

#ifndef P11C_OBJECT_H
#define P11C_OBJECT_H

#include "p11-capi.h"

/* A function to load data for an object */
typedef CK_RV (*P11cLoadData)(P11cSession* sess, struct _P11cObject* obj, 
                              P11cObjectData** objdata);

/* Produce a hash code for an object */
typedef CK_RV (*P11cHashObject)(struct _P11cObject* obj);

/* Produce a hash code for an object */
typedef CK_RV (*P11cEqualObject)(struct _P11cObject* one, struct _P11cObject* two);

/* A function to free some data */
typedef void (*P11cRelease)(void* data);

/* Object functions */
typedef struct _P11cObjectVtable
{
	P11cLoadData load_data;
	P11cHashObject hash_object;
	P11cEqualObject equal_object;
	P11cRelease release;
}
P11cObjectVtable;

/* Represents a object we've seen */
struct _P11cObject
{
	CK_OBJECT_HANDLE id;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	const P11cObjectVtable* obj_funcs;
};

/* A function to get an attribute from ObjectData */
typedef CK_RV (*P11cGetAttribute)(P11cObjectData* objdata, CK_ATTRIBUTE_PTR attr);

/* Object data functions */
typedef struct _P11cObjectDataVtable
{
	P11cGetAttribute get_bool;
	P11cGetAttribute get_ulong;
	P11cGetAttribute get_bytes;
	P11cRelease release;
}
P11cObjectDataVtable;

/* 
 * Base class for object data. Different types of 
 * objects extend this with more detailed data 
 */
struct _P11cObjectData
{
	CK_OBJECT_HANDLE object;
	const P11cObjectDataVtable* data_funcs;
};

/* Match object data against all the given match attributes */
CK_BBOOL            p11c_object_data_match       (P11cObjectData* objdata, 
                                                  CK_ATTRIBUTE_PTR matches, CK_ULONG count);

/* Match a single attribute against object data */
CK_BBOOL            p11c_object_data_match_attr  (P11cObjectData* objdata, 
                                                  CK_ATTRIBUTE_PTR match);

/* Get a bunch of attributes from object data */
CK_RV               p11c_object_data_get_attrs   (P11cObjectData* objdata, CK_ATTRIBUTE_PTR attrs, 
                                                  CK_ULONG count);

/* Debug print something about an object or object data */
#if DBG_OUTPUT
#define DBGO(obj, msg)          p11c_log("O%d: %s", (obj) ? (obj)->id : 0, (msg))
#define DBGOD(objdata, msg)	    p11c_log("O%d: %s", (objdata) ? (objdata)->obj : 0, (msg))
#else
#define DBGO(obj, msg)
#define DBGOD(objdata, msg)
#endif

#endif /* P11C_OBJECT_H */

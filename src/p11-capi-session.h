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

#ifndef P11C_SESSION_H
#define P11C_SESSION_H

#include "p11-capi.h"

/* --------------------------------------------------------------------
 * 
 * Session = P11cSession
 * - A PKCS#11 Session 
 * 
 * Objects = P11cObject
 * - There's a global list of objects in p11c-object.c indexed by 
 *   object handle. 
 * - The object itself has no attributes or cached data, but knows how 
 *   to load data when needed. 
 * - Each object has a unique key which guarantees we don't load the 
 *   same object twice with two different object handles.
 * 
 * Object Data = P11cObjectData
 * - Object Data is owned by the Session
 * - Loaded data and/or attributes for an object. 
 */

/* Callback to cleanup a current operation */
typedef void (*P11cSessionCancel) (struct _P11cSession* sess);

/* Represents an open session */
typedef struct _P11cSession 
{
	CK_SESSION_HANDLE id;                  /* Unique ID for this session */
	CK_SLOT_ID slot;
	int in_call;                           /* Whether this session is use in PKCS#11 function */

	HCERTSTORE store;                      /* Handle to an open certificate store */

	BOOL read_write;                       /* A read-write session? */

	int operation_type;                    /* Whether an operation is happening or not */
	void* operation_data;                  /* Data for this operation */
	P11cSessionCancel operation_cancel;    /* Callback to cancel operation when necessary */

	P11cHash* object_data;

	CK_NOTIFY notify_callback;             /* Application specified callback */
	CK_VOID_PTR user_data;                 /* Argument for above */

	int refs;                              /* Reference count */
	HANDLE mutex;                          /* Mutex for protecting this structure */
} 
P11cSession;

/* Debug print something related to a session */
#if DBG_OUTPUT
#define DBGS(sess, msg)     p11c_log("S%d: %s", (sess) ? (sess)->id : 0, (msg))
#else
#define DBGS(sess, msg)
#endif

#define WARNS(sess, msg)    p11c_log("S%d: %s", (sess) ? (sess)->id : 0, (msg))

/* Create a session */
CK_RV           p11c_session_create              (CK_SLOT_ID slot, P11cSession** ret);

/* Destroy a session */
void            p11c_session_destroy             (P11cSession* sess);

/* Register a new session */
CK_RV           p11c_session_register            (P11cSession* sess);

/* Get information about a session */
void            p11c_session_get_info            (P11cSession* sess, 
                                                  CK_SESSION_INFO_PTR info);

/* Get a session from a handle, and lock it */
CK_RV           p11c_session_get_lock_ref        (CK_ULONG id, BOOL writable, 
                                                  P11cSession **sess);

/* Get a session from a handle, remove it from list, and lock it */
CK_RV           p11c_session_remove_lock_ref     (CK_ULONG id, P11cSession **sess);

/* Unlock and unreference a session */
void            p11c_session_unref_unlock        (P11cSession* sess);

/* Close all sessions on a certain slot/token */
CK_RV           p11c_session_close_all           (CK_SLOT_ID slot);



/* Start a find operation on a session */
CK_RV           p11c_session_find_init           (P11cSession* sess, 
                                                  CK_ATTRIBUTE_PTR templ, 
                                                  CK_ULONG count);

/* Return results from a find operation */
CK_RV           p11c_session_find                (P11cSession* sess, 
                                                  CK_OBJECT_HANDLE_PTR objects, 
                                                  CK_ULONG max_object_count, 
                                                  CK_ULONG_PTR object_count);

/* End a find operation */
CK_RV           p11c_session_find_final          (P11cSession* sess);


/* Start a sign operation on a session */
CK_RV           p11c_session_sign_init           (P11cSession* sess, 
                                                  CK_MECHANISM_PTR mech, 
                                                  P11cObjectData *objdata);

/* Perform sign operation */
CK_RV           p11c_session_sign                (P11cSession* sess, 
                                                  CK_BYTE_PTR data, CK_ULONG n_data,
                                                  CK_BYTE_PTR sig, CK_ULONG_PTR n_sig);

/* Start a decrypt operation on a session */
CK_RV           p11c_session_decrypt_init        (P11cSession* sess, 
                                                  CK_MECHANISM_PTR mech, 
                                                  P11cObjectData *objdata);

/* Perform decrypt operation */
CK_RV           p11c_session_decrypt             (P11cSession* sess, 
                                                  CK_BYTE_PTR encdata, CK_ULONG n_encdata,
                                                  CK_BYTE_PTR result, CK_ULONG_PTR n_result);

/* Get object data for an object */
CK_RV           p11c_session_get_object_data     (P11cSession* sess, 
                                                  P11cObject* obj, 
                                                  P11cObjectData** objdata);

/* Get object data for an object handle */
CK_RV           p11c_session_get_object_data_for (P11cSession* sess, 
                                                  CK_OBJECT_HANDLE hand, 
                                                  P11cObjectData** objdata);

/* Set object data for an object */
void            p11c_session_take_object_data    (P11cSession* sess, 
                                                  P11cObject* obj, 
                                                  P11cObjectData* objdata);

/* Clear object data for an object */
void            p11c_session_clear_object_data   (P11cSession* sess, 
                                                  P11cObject* obj);

/* Enumerate object data for all objects */
typedef void    (*P11cEnumObjectData)            (P11cSession* sess, 
                                                  P11cObject* obj, 
                                                  P11cObjectData* data, 
                                                  void* arg);

void            p11c_session_enum_object_data    (P11cSession* sess, 
                                                  P11cEnumObjectData enum_func, 
                                                  void* arg);

void            p11c_session_cleanup_all         (void);

#endif /* P11C_SESSION_H */

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

#include <stdlib.h>

#include "p11-capi.h"
#include "p11-capi-builtin.h"
#include "p11-capi-cert.h"
#include "p11-capi-key.h"
#include "p11-capi-object.h"
#include "p11-capi-rsa.h"
#include "p11-capi-session.h"
#include "p11-capi-token.h"
#include "p11-capi-trust.h"

/* For operation_type in P11cSession */
enum
{
	OPERATION_NONE,
	OPERATION_FIND,
	OPERATION_SIGN,
	OPERATION_DECRYPT
};

static P11cArray* all_sessions = NULL;

static void
object_data_release(P11cObjectData* objdata)
{
	ASSERT(objdata->data_funcs);
	ASSERT(objdata->data_funcs->release);
	(objdata->data_funcs->release)(objdata);
}

CK_RV
p11c_session_create(CK_SLOT_ID slot, P11cSession** ret)
{
	P11cSession* sess;
	const char *store;
	DWORD err;
	
	sess = calloc(1, sizeof(P11cSession));
	if(!sess)
		return CKR_HOST_MEMORY;

	sess->object_data = p11c_hash_new(NULL, NULL);
	if(!sess->object_data) {
		free(sess);
		return CKR_HOST_MEMORY;
	}
	
	sess->mutex = CreateMutex(NULL, FALSE, NULL);
	if(!sess->mutex) {
		p11c_hash_free(sess->object_data, NULL);
		free(sess);
		return CKR_HOST_MEMORY;
	}

	store = p11c_token_get_store_name(slot);
	if(store)
	{
		sess->store = CertOpenSystemStore((HCRYPTPROV)NULL, store);
		if(sess->store == NULL)
		{
			err = GetLastError();

			/* Store not found, we don't care */
			if(err != ERROR_FILE_NOT_FOUND)
			{
				p11c_hash_free(sess->object_data, NULL);
				CloseHandle(sess->mutex);
				free(sess);
				return p11c_winerr_to_ckr(err);
			}
		}
	}

	sess->slot = slot;

	DBGS(sess, "created");

	*ret = sess;
	return CKR_OK;
}

CK_RV 
p11c_session_register(P11cSession* sess)
{
	P11cSession* blank = NULL;
	CK_SESSION_HANDLE id = 0;
	CK_RV ret = CKR_OK;
	size_t i;

	ASSERT(sess);
	ASSERT(sess->id == 0 && sess->refs == 0);

	DBGS(sess, "registering new session");

	p11c_lock_global();

		/* Find a nice session identifier */
		while(id == 0) {

			/* Allocate sessions properly */
			if(!all_sessions)
			{
				all_sessions = p11c_array_new(0, 1, sizeof(P11cSession*));
				if(!all_sessions)
				{
					ret = CKR_HOST_MEMORY;
					break;
				}

				/* A blank entry for '0' */
				p11c_array_append(all_sessions, blank);

				DBG(("allocated new session list"));
			}

			/* 
			 * PKCS#11 GRAY AREA: We're assuming we can reuse session
			 * handles. PKCS#11 spec says they're like file handles,
			 * and file handles get reused :)
			 */
			
			/* Note we never put anything in array position '0' */
			for(i = 1; i < all_sessions->len; ++i) 
			{
				/* Any empty position will do */
				if(!p11c_array_index(all_sessions, P11cSession*, i))
				{
					id = i;
					break;
				}
			}

			/* Couldn't find a handle, append a handle */
			if(id == 0)
			{
				id = all_sessions->len;
				p11c_array_append(all_sessions, blank);
			}
		}

		if(ret == CKR_OK) 
		{
			ASSERT(id > 0 && id < all_sessions->len);
			ASSERT(!p11c_array_index(all_sessions, P11cSession*, id));


			/* And assign it to the session handle */
			p11c_array_index(all_sessions, P11cSession*, i) = sess;
			sess->id = id;
			
			/* The session list reference */
			ASSERT(sess->refs == 0);
			sess->refs++;
			
			DBGS(sess, "registered sesson id");
		}

	p11c_unlock_global();

	return ret;
}

void
p11c_session_destroy(P11cSession* sess)
{
	ASSERT(sess);
	ASSERT(sess->refs == 0);

	/* Ask any pending operations to cleanup */
	if(sess->operation_type)
	{
		ASSERT(sess->operation_cancel);
		(sess->operation_cancel)(sess);
	}

	ASSERT(sess->operation_type == 0);
	ASSERT(sess->operation_data == NULL);
	ASSERT(sess->operation_cancel == NULL);

	if(sess->store)
		CertCloseStore(sess->store, 0);

	/* Make all the object adat go away */
	ASSERT(sess->object_data != NULL);
	p11c_hash_free(sess->object_data, object_data_release);

	/* And make the mutex go away */
	ASSERT(sess->mutex != NULL);
	CloseHandle(sess->mutex);
	
	DBGS(sess, "destroyed");
	free(sess);
}

void
p11c_session_get_info(P11cSession* sess, CK_SESSION_INFO_PTR info)
{
	ASSERT(sess);
	ASSERT(info);

	info->slotID = sess->slot;
	info->flags = CKF_SERIAL_SESSION;
	if(sess->read_write)
		info->flags |= CKF_RW_SESSION;

	if(p11c_token_is_logged_in(sess->slot))
		info->state = sess->read_write ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
	else
		info->state = sess->read_write ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;

	/* TODO: We could implement some use of GetLastError() here */
	info->ulDeviceError = 0;
}

static CK_RV 
lock_ref_internal(P11cArray* sessions, CK_SESSION_HANDLE id, 
                  BOOL remove, BOOL writable, P11cSession** sess_ret)
{
	P11cSession *sess;
	DWORD r;
	
	ASSERT(sessions);
	ASSERT(sess_ret);
	
	if(id >= sessions->len) 
	{
		WARN(("invalid session id: %d", id));
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* A seemingly valid id */
	ASSERT(sessions);
	sess = p11c_array_index(sessions, P11cSession*, id);
	
	if(!sess) 
	{
		WARN(("session does not exist: %d", id));
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* Make sure it's the right kind of session */
	if(writable && !sess->read_write)
		return CKR_SESSION_READ_ONLY;

	ASSERT(sess->id == id);
	
	/* Closing takes precedence over active operations */
	if(!remove) 
	{
		/* 
		 * An initial check is done to make sure this session is not active. 
		 * This is done outside of the lock. The real check is done later 
		 * inside a lock. This is so we can return quickly without blocking
		 * in most cases. 
		 */
	
		if(sess->in_call) 
		{
			WARNS(sess, ("an operation is already active in this session"));
			return CKR_OPERATION_ACTIVE;
		}
	}

	/* Lock the CallP11cSession */
	r = WaitForSingleObject(sess->mutex, INFINITE);
	ASSERT(r == WAIT_OBJECT_0);

	/* Do the real check */
	if(!remove && sess->in_call) 
	{
		ReleaseMutex(sess->mutex);
		WARNS(sess, ("an operation is already active in this session"));
		return CKR_OPERATION_ACTIVE;
	}

	/* Make sure it doesn't go away */
	ASSERT(sess->refs > 0);
	sess->refs++;

	DBGS(sess, "found and locked session");
	
	/* And remove it if necessary */
	if(remove) 
	{
		p11c_array_index(sessions, P11cSession*, id) = NULL;
		
		/* The session list reference */
		sess->refs--;
		ASSERT(sess->refs > 0);
		
		DBGS(sess, "removed session from list");
	}
	else
	{
		ASSERT(!sess->in_call);
		sess->in_call = 1;
	}
	
	*sess_ret = sess;
	return CKR_OK;
}

CK_RV
p11c_session_get_lock_ref(CK_ULONG id, BOOL writable, P11cSession **sess)
{
	/* This must be called without any locks held */

	CK_RV ret = CKR_OK;

	ASSERT(sess);
	
	if(id <= 0)
	{
		WARN(("invalid session id passed: %d", id));
		return CKR_ARGUMENTS_BAD;
	}
	
	p11c_lock_global();
	
		ret = lock_ref_internal (all_sessions, id, FALSE, writable, sess);

	p11c_unlock_global();
	
	return ret;
}

CK_RV
p11c_session_remove_lock_ref(CK_ULONG id, P11cSession **sess)
{
	/* This must be called without any locks held */

	CK_RV ret = CKR_OK;

	ASSERT(sess);
	
	if(id <= 0)
	{
		WARN(("invalid session id passed: %d", id));
		return CKR_ARGUMENTS_BAD;
	}
	
	p11c_lock_global();
	
		ret = lock_ref_internal (all_sessions, id, TRUE, FALSE, sess);

	p11c_unlock_global();
	
	return ret;
}

void
p11c_session_unref_unlock(P11cSession* sess)
{
	/* The CallP11cSession must be locked at this point */

	int refs;
	BOOL r;
	
	ASSERT(sess);
	
	ASSERT(sess->refs > 0);
	sess->refs--;
	refs = sess->refs;

	sess->in_call = 0;

	DBGS(sess, "unlocked session");

	r = ReleaseMutex(sess->mutex);
	ASSERT(r == TRUE);
	
	/* 
	 * At this point if no references are held, then we can safely 
	 * delete. No other thread should be involved. 
	 */
	
	if(refs == 0)
		p11c_session_destroy(sess);
}

CK_RV 
p11c_session_close_all(CK_SLOT_ID slot)
{
	/* This must be called without any locks held */
	
	P11cArray* sessions;
	P11cSession *sess;
	size_t i;
	CK_RV ret = CKR_OK;

	/* 
	 * PKCS#11 GRAY AREA: What happens when this gets called 
	 * concurrently? We don't return an error on the second call,
	 * because by the time it returns, all sessions should be closed.
	 */

	DBG(("closing all sessions for: %d", slot));

	if(!all_sessions)
		return CKR_OK;

	p11c_lock_global();

		sessions = p11c_array_sized_new(0, 1, sizeof(P11cSession*), 
										  all_sessions->len);
		if(!sessions)
			ret = CKR_HOST_MEMORY;

		/* Steal all the session data */
		if(ret == CKR_OK)
		{
			for(i = 0; i < all_sessions->len; ++i)
			{
				sess = p11c_array_index(all_sessions, P11cSession*, i);
				if(sess && (slot == ((CK_SLOT_ID)-1) || sess->slot == slot))
				{
					/* Steal this session */
					p11c_array_index(all_sessions, P11cSession*, i) = NULL;
				}
				else
				{
					/* Not a session we're interested in */
					sess = NULL;
				}

				/* Both null and normal sessions are set to preserve indexes */
				p11c_array_append(sessions, sess);
			}

			ASSERT(sessions->len == all_sessions->len);
		}

	p11c_unlock_global();

	if(ret != CKR_OK)
		return ret;

	/* Close each session in turn */
	for(i = 0; i < sessions->len; ++i) 
	{
		if(!p11c_array_index(sessions, P11cSession*, i))
			continue;

		/* We need any calls in other threads to finish, so wait here */
		if(lock_ref_internal(sessions, i, TRUE, FALSE, &sess) == CKR_OK)
			p11c_session_unref_unlock(sess);
	}

	/* We stole the memory above, free it now */
	p11c_array_free(sessions, 1);
	return CKR_OK;
}

void
p11c_session_cleanup_all()
{
	p11c_session_close_all((CK_SLOT_ID)-1);

	p11c_lock_global();

		p11c_array_free(all_sessions, 1);
		all_sessions = NULL;

	p11c_unlock_global();
}

/* ----------------------------------------------------------------------------
 * OBJECT DATA
 */

CK_RV
p11c_session_get_object_data(P11cSession* sess, P11cObject* obj, 
                             P11cObjectData** objdata)
{
	CK_OBJECT_HANDLE id;
	P11cObjectData* newdata;
	CK_RV ret;

	ASSERT(sess);
	ASSERT(sess->object_data);
	ASSERT(obj);
	ASSERT(obj->obj_funcs);
	ASSERT(obj->obj_funcs->load_data);
	ASSERT(objdata);

	id = obj->id;

	*objdata = p11c_hash_get(sess->object_data, p11c_hash_key(id));
	if(*objdata)
		return CKR_OK;

	ret = (obj->obj_funcs->load_data)(sess, obj, &newdata);
	if(ret != CKR_OK)
		return ret;

	newdata->object = id;
	ASSERT(newdata->data_funcs);

	if(!p11c_hash_set(sess->object_data, p11c_hash_key(id), newdata)) 
	{
		object_data_release(newdata);
		return CKR_HOST_MEMORY;
	}

	*objdata = newdata;
	return CKR_OK;
}

void
p11c_session_clear_object_data(P11cSession* sess, P11cObject* obj)
{
	P11cObjectData* objdata;

	ASSERT(sess);
	ASSERT(sess->object_data);
	ASSERT(obj);

	objdata = (P11cObjectData*)p11c_hash_rem(sess->object_data, p11c_hash_key(obj->id));
	if(objdata)
		object_data_release(objdata);
}

void
p11c_session_enum_object_data(P11cSession* sess, 
                              P11cEnumObjectData enum_func, void* arg)
{
	CK_OBJECT_HANDLE i, max;
	P11cObject* obj;
	P11cObjectData* objdata;

	ASSERT(sess);
	ASSERT(sess->object_data);
	ASSERT(enum_func);

	max = p11c_token_get_max_handle();
	for(i = 0; i < max; ++i)
	{
		objdata = (P11cObjectData*)p11c_hash_get(sess->object_data, p11c_hash_key(i));
		if(!objdata)
			continue;

		obj = p11c_token_lookup_object(sess->slot, i);
		if(!obj)
			continue;

		(enum_func)(sess, obj, objdata, arg);
	}
}

CK_RV
p11c_session_get_object_data_for(P11cSession* sess, CK_OBJECT_HANDLE hand, 
                                 P11cObjectData** objdata)
{
	P11cObject* obj;

	obj = p11c_token_lookup_object(sess->slot, hand);
	if(!obj)
		return CKR_OBJECT_HANDLE_INVALID;

	return p11c_session_get_object_data(sess, obj, objdata);
}

void
p11c_session_take_object_data(P11cSession* sess, P11cObject* obj, 
                              P11cObjectData* objdata)
{
	P11cObjectData* prev;

	ASSERT(obj);
	ASSERT(sess);
	ASSERT(sess->object_data);

	ASSERT(objdata);
	objdata->object = obj->id;
	
	prev = p11c_hash_rem(sess->object_data, p11c_hash_key(obj->id));
	if(prev)
		object_data_release(prev);

	if(!p11c_hash_set(sess->object_data, p11c_hash_key(obj->id), objdata))
		object_data_release(objdata);
}


/* ----------------------------------------------------------------------------
 * FIND OPERATION
 */

static BOOL
get_ulong_attribute(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE_PTR templ, 
                    CK_ULONG count, CK_ULONG* val)
{
	CK_ULONG i;

	ASSERT(val);
	ASSERT(!count || templ);

	for(i = 0; i < count; ++i)
	{
		if(templ[i].type == type)
		{
			*val = *((CK_ULONG*)templ[i].pValue);
			return TRUE;
		}
	}

	return FALSE;
}

static CK_RV
gather_objects(P11cSession* sess, CK_ATTRIBUTE_PTR match, 
               CK_ULONG count, P11cArray* arr)
{
	CK_OBJECT_CLASS ocls = CKO_ANY;
	CK_RV ret = CKR_OK;

	get_ulong_attribute(CKA_CLASS, match, count, &ocls);

	/* Search for builtins */
	ret = p11c_builtin_find(sess, ocls, match, count, arr);
	if(ret != CKR_OK)
		return ret;

	/*
	 * Search through certificates.
	 * 
	 * We always do this search first. In Windows a lots hangs off 
	 * the certificates. For example private keys are not contained
	 * in the same stores that certificates are in. There are a different
	 * set of key containers many of which can be used together 
	 * with a certificate stored in any store.
	 * 
	 * The trust objects we expose also depend on the certificates 
	 * loaded. 
	 */
	ret = p11c_cert_find(sess, ocls, match, count, arr);
	if(ret != CKR_OK)
		return ret;

	/* Search through trust objects */
	ret = p11c_trust_find(sess, ocls, match, count, arr);
	if(ret != CKR_OK)
		return ret;

	/* Search through key objects */
	ret = p11c_key_find(sess, ocls, match, count, arr);
	if(ret != CKR_OK)
		return ret;

	return ret;
}

void 
cleanup_find_operation(P11cSession* sess)
{
	ASSERT(sess->operation_type == OPERATION_FIND);
	if(sess->operation_data)
		p11c_array_free((P11cArray*)sess->operation_data, TRUE);
	sess->operation_type = OPERATION_NONE;
	sess->operation_data = NULL;
	sess->operation_cancel = NULL;
}

void 
purge_duplicate_objects(P11cArray* arr)
{
	P11cHash* checks;
	CK_OBJECT_HANDLE v;
	size_t i;

	checks = p11c_hash_new(NULL, NULL);
	if(!checks)
		return;

	for(i = 0; i < arr->len; )
	{
		v = p11c_array_index(arr, CK_OBJECT_HANDLE, i);
		if(p11c_hash_get(checks, p11c_hash_key(v)))
		{
			p11c_array_remove_index(arr, i);
			/* Look at same i again */
		}
		else
		{
			if(!p11c_hash_set(checks, p11c_hash_key(v), arr))
				break;
			++i;
		}
	}

	p11c_hash_free(checks, NULL);
}

CK_RV
p11c_session_find_init(P11cSession* sess, CK_ATTRIBUTE_PTR match, 
                       CK_ULONG count)
{
	P11cArray* arr;
	CK_RV ret;

	ASSERT(sess);
	ASSERT(!count || match);

	if(sess->operation_type != OPERATION_NONE)
		return CKR_OPERATION_ACTIVE;

	arr = p11c_array_new(0, 1, sizeof(CK_OBJECT_HANDLE));
	if(!arr)
		return CKR_HOST_MEMORY;

	ret = gather_objects(sess, match, count, arr);
	if(ret != CKR_OK) 
	{
		p11c_array_free(arr, TRUE);
		return ret;
	}

	/* Cleanup all duplicates in the array */
	purge_duplicate_objects(arr);

	sess->operation_type = OPERATION_FIND;
	sess->operation_data = arr;
	sess->operation_cancel = cleanup_find_operation;

	return CKR_OK;
}

CK_RV
p11c_session_find(P11cSession* sess, CK_OBJECT_HANDLE_PTR objects, 
                  CK_ULONG max_object_count, CK_ULONG_PTR object_count)
{
	P11cArray* arr;
	size_t i;

	ASSERT(sess);
	ASSERT(object_count);
	ASSERT(!max_object_count || objects);

	if(sess->operation_type != OPERATION_FIND)
		return CKR_OPERATION_NOT_INITIALIZED;

	if(!max_object_count)
	{
		*object_count = 0;
		return CKR_OK;
	}

	arr = (P11cArray*)sess->operation_data;
	*object_count = (max_object_count > arr->len ? arr->len : max_object_count);
	for(i = 0; i < *object_count; ++i)
		objects[i] = p11c_array_index(arr, CK_OBJECT_HANDLE, i);

	p11c_array_remove_range(arr, 0, *object_count);

	return CKR_OK;
}

CK_RV
p11c_session_find_final(P11cSession* sess)
{
	ASSERT(sess);

	if(sess->operation_type != OPERATION_FIND)
		return CKR_OPERATION_NOT_INITIALIZED;

	cleanup_find_operation(sess);
	return CKR_OK;
}


/* ----------------------------------------------------------------------------
 * CRYPTO OPERATIONS
 */

typedef struct _CryptoContext 
{
	CK_MECHANISM_TYPE mech_type;
	P11cDestroyFunc mech_cleanup;
	void* mech_data;
}
CryptoContext;

void 
cleanup_crypto_operation(P11cSession* sess)
{
	CryptoContext* ctx;

	if(sess->operation_data)
	{
		ctx = (CryptoContext*)sess->operation_data;
		if(ctx->mech_cleanup)
			(ctx->mech_cleanup)(ctx->mech_data);
		free(ctx);
	}

	sess->operation_type = OPERATION_NONE;
	sess->operation_data = NULL;
	sess->operation_cancel = NULL;
}

CK_RV
p11c_session_sign_init(P11cSession* sess, CK_MECHANISM_PTR mech, 
                       P11cObjectData *objdata)
{
	CryptoContext* ctx;
	CK_RV ret;

	ASSERT(sess);
	ASSERT(mech);
	ASSERT(objdata);

	if(sess->operation_type != OPERATION_NONE)
		return CKR_OPERATION_ACTIVE;

	ctx = calloc(1, sizeof(CryptoContext));
	if(!ctx)
		return CKR_HOST_MEMORY;

	ctx->mech_type = mech->mechanism;

	switch(mech->mechanism)
	{
	case CKM_RSA_PKCS:
		ret = p11c_rsa_pkcs_sign_init(objdata, &ctx->mech_data);
		ctx->mech_cleanup = p11c_rsa_pkcs_sign_cleanup;
		break;
	default:
		ret = CKR_MECHANISM_INVALID;
		break;
	};

	if(ret != CKR_OK)
	{
		free(ctx);
		ASSERT(!sess->operation_data);
		return ret;
	}

	sess->operation_type = OPERATION_SIGN;
	sess->operation_data = ctx;
	sess->operation_cancel = cleanup_crypto_operation;
	return CKR_OK;
}

CK_RV
p11c_session_sign(P11cSession* sess, CK_BYTE_PTR data, CK_ULONG n_data,
                  CK_BYTE_PTR signature, CK_ULONG_PTR n_signature)
{
	CryptoContext *ctx;
	BOOL incomplete;
	CK_RV ret;

	ASSERT(sess);
	ASSERT(data);
	ASSERT(n_data);

	if(sess->operation_type != OPERATION_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	ctx = (CryptoContext*)sess->operation_data;
	switch(ctx->mech_type)
	{
	case CKM_RSA_PKCS:
		ret = p11c_rsa_pkcs_sign_perform(data, n_data, signature, n_signature,
		                                 &ctx->mech_data);
                p11c_log("checkpoint (ret = %d) at %s, line %d", ret, __FILE__, __LINE__); 
		break;

	default:
		ASSERT(FALSE);
                p11c_log("session sign");
		ret = CKR_GENERAL_ERROR;
		break;
	}

	/* Buffer calculation, we don't end operation */
	incomplete = (ret == CKR_BUFFER_TOO_SMALL || (ret == CKR_OK && !signature));

	if(!incomplete)
		cleanup_crypto_operation(sess);

	return ret;
}

CK_RV
p11c_session_decrypt_init(P11cSession* sess, CK_MECHANISM_PTR mech, 
                          P11cObjectData *objdata)
{
	CryptoContext* ctx;
	CK_RV ret;

	ASSERT(sess);
	ASSERT(mech);
	ASSERT(objdata);

	if(sess->operation_type != OPERATION_NONE)
		return CKR_OPERATION_ACTIVE;

	ctx = calloc(1, sizeof(CryptoContext));
	if(!ctx)
		return CKR_HOST_MEMORY;

	ctx->mech_type = mech->mechanism;

	switch(mech->mechanism)
	{
	case CKM_RSA_PKCS:
		ret = p11c_rsa_pkcs_decrypt_init(objdata, &ctx->mech_data);
		ctx->mech_cleanup = p11c_rsa_pkcs_decrypt_cleanup;
		break;
	default:
		ret = CKR_MECHANISM_INVALID;
		break;
	};

	if(ret != CKR_OK)
	{
		free(ctx);
		ASSERT(!sess->operation_data);
		return ret;
	}

	sess->operation_type = OPERATION_DECRYPT;
	sess->operation_data = ctx;
	sess->operation_cancel = cleanup_crypto_operation;
	return CKR_OK;
}

CK_RV
p11c_session_decrypt(P11cSession* sess,  CK_BYTE_PTR encdata, CK_ULONG n_encdata,
                     CK_BYTE_PTR result, CK_ULONG_PTR n_result)
{
	CryptoContext *ctx;
	BOOL incomplete;
	CK_RV ret;

	ASSERT(sess);
	ASSERT(encdata);
	ASSERT(n_encdata);

	if(sess->operation_type != OPERATION_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	ctx = (CryptoContext*)sess->operation_data;
	switch(ctx->mech_type)
	{
	case CKM_RSA_PKCS:
		ret = p11c_rsa_pkcs_decrypt_perform(encdata, n_encdata, result, n_result,
		                                    &ctx->mech_data);
		break;

	default:
		ASSERT(FALSE);
                p11c_log("session decrypt");
		ret = CKR_GENERAL_ERROR;
		break;
	}

	/* Buffer calculation, we don't end operation */
	incomplete = (ret == CKR_BUFFER_TOO_SMALL || (ret == CKR_OK && !result));

	if(!incomplete)
		cleanup_crypto_operation(sess);

	return ret;
}

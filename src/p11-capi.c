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

#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "p11-capi.h"
#include "p11-capi-object.h"
#include "p11-capi-session.h"
#include "p11-capi-rsa.h"
#include "p11-capi-token.h"

/* Warns about all the raw string usage in this file */
#pragma warning (disable : 4996)

/* -------------------------------------------------------------------
 * GLOBALS / DEFINES 
 */

static int cryptoki_initialized = 0;
static HANDLE global_mutex = NULL;

#define MANUFACTURER_ID         "p11-capi                        "
#define LIBRARY_DESCRIPTION     "PKCS#11 CAPI Provider           "
#define LIBRARY_VERSION_MAJOR   1
#define LIBRARY_VERSION_MINOR   1
#define HARDWARE_VERSION_MAJOR  0
#define HARDWARE_VERSION_MINOR  0
#define FIRMWARE_VERSION_MAJOR  0
#define FIRMWARE_VERSION_MINOR  0
#define SLOT_TOKEN_SERIAL       "1.0             "
#define SLOT_TOKEN_MODEL        "1.0             "
#define MAX_PIN_LEN             256
#define MIN_PIN_LEN             1

static CK_MECHANISM_TYPE all_mechanisms[] = {
	CKM_RSA_PKCS
};

#ifdef FILE_LOGGING

static FILE* output_file = NULL;

#endif


/* -------------------------------------------------------------------
 * MODULE GLOBAL FUNCTIONS
 */

#define LINE 1024

void 
p11c_log(const char* msg, ...)
{
	char buf[LINE];
	va_list va;
	size_t len;

	va_start(va, msg);
	_vsnprintf(buf, 1024, msg, va);
	va_end(va);

	buf[LINE - 1] = 0;
	len = strlen (buf);

	strncpy(buf + len, "\n", 1024 - len);
	buf[LINE - 1] = 0;
	OutputDebugStringA(buf);
#ifdef FILE_LOGGING
        if (output_file) {
          fputs(buf, output_file);
          /*          backtrace(buf, LINE);
                      fputs(buf, output_file); */
          fflush (output_file);
        }
#endif
        
}


/* Bah humbug, MSVC doesn't have __func__ */
#if DBG_OUTPUT
#define p11c_debug p11c_log

#define ENTER(func)	\
	char* _func = #func; \
	p11c_debug("%s: enter", _func)

#define RETURN(ret) \
	return (p11c_debug("%s: %d", _func, ret), ret)

#else /* !DBG_OUTPUT */

#define ENTER(func) \
	char* _func = #func;

#define RETURN(ret) \
	return log_return(_func, ret)

static CK_RV
log_return(char *func, CK_RV ret)
{
	if(ret != CKR_OK)
		p11c_log("%s: %d", func, ret);
	return ret;
}

#endif /* !DBG_OUTPUT */

#define PREREQ(cond, ret) \
	if (!(cond)) { p11c_log("%s: %s failed: %d", _func, #cond, ret); return ret; }

void 
p11c_lock_global(void)
{
	DWORD r;

	ASSERT(global_mutex);
	
	r = WaitForSingleObject(global_mutex, INFINITE);
	ASSERT(r == WAIT_OBJECT_0);
}

void 
p11c_unlock_global(void)
{
	BOOL r;

	ASSERT(global_mutex);

	r = ReleaseMutex(global_mutex);
	ASSERT(r);
}

CK_RV
p11c_winerr_to_ckr(DWORD werr)
{
	switch(werr) 
	{
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_OUTOFMEMORY:
		return CKR_HOST_MEMORY;
		break;
	case NTE_NO_MEMORY:
		return CKR_DEVICE_MEMORY;
		break;
	case ERROR_MORE_DATA:
		return CKR_BUFFER_TOO_SMALL;
	case ERROR_INVALID_PARAMETER: /* these params were derived from the */
	case ERROR_INVALID_HANDLE:    /* inputs, so if they are bad, the input */ 
	case NTE_BAD_ALGID:           /* data is bad */
	case NTE_BAD_HASH:
	case NTE_BAD_TYPE:
         case NTE_BAD_KEYSET:
	case NTE_BAD_PUBLIC_KEY:
		return CKR_DATA_INVALID;
	case ERROR_BUSY:
	case NTE_FAIL:
	case NTE_BAD_UID:
		return CKR_DEVICE_ERROR;
	default:
          p11c_log("default windows error 0x%X", werr);
		return CKR_GENERAL_ERROR;
	};
}

CK_RV
p11c_return_data_raw(CK_VOID_PTR output, CK_ULONG_PTR n_output,
                     CK_VOID_PTR input, CK_ULONG n_input)
{
	ASSERT(n_output);
	ASSERT(input);

	/* Just asking for the length */
	if(!output)
	{
		*n_output = n_input;
		return CKR_OK;
	}

	/* Buffer is too short */
	if(n_input > *n_output)
	{
		*n_output = n_input;
		return CKR_BUFFER_TOO_SMALL;
	}

	*n_output = n_input;
	memcpy(output, input, n_input);
	return CKR_OK;
}

CK_RV
p11c_return_data(CK_ATTRIBUTE_PTR attr, CK_VOID_PTR input, DWORD n_input)
{
	return p11c_return_data_raw(attr->pValue, &(attr->ulValueLen),
	                            input, n_input);
}

CK_RV
p11c_return_string(CK_ATTRIBUTE_PTR attr, WCHAR* string)
{
	CK_UTF8CHAR_PTR buffer;
	int result;

	SetLastError(0);

	/* 
	 * Sadly WideCharToMultiByte doesn't handle zero 
	 * length strings properly. So we have to special
	 * case this part.
	 */
	if(!string[0])
		return p11c_return_data(attr, "", 0);

	/* The length of the string, including null termination */
	result = WideCharToMultiByte(CP_UTF8, 0, string, -1, 
	                             NULL, 0, NULL, NULL);

	if(result)
	{
		/* Did the caller just want the length? */
		if(!attr->pValue)
		{
			attr->ulValueLen = result - 1;
			return CKR_OK;
		}

		/* Is the callers buffer too short? */
		if((int)attr->ulValueLen < result - 1)
		{
			attr->ulValueLen = result - 1;
			return CKR_BUFFER_TOO_SMALL;
		}

		/* 
		 * Allocate a buffer for the conversion. We have to 
		 * do this because strings in PKCS#11 are not null
		 * terminated and strings returned from 
		 * WideCharToMultiByte are always null terminated.
		 */
		buffer = malloc(result);
		if(!buffer)
			return CKR_HOST_MEMORY;

		/* Do the actual conversion */
		result = WideCharToMultiByte(CP_UTF8, 0, string, -1, 
		                             buffer, result, NULL, NULL);

		if(result)
		{
			attr->ulValueLen = result - 1;
			memcpy(attr->pValue, buffer, attr->ulValueLen);

			free(buffer);
			return CKR_OK;
		}

		free(buffer);
	}

	/*
	 * We should never have too little buffer, or 
	 * get a zero length success code. It's a very 
	 * strange error that arrives here.
	 */
        
	p11c_log("p11c_return_string");
	return CKR_GENERAL_ERROR;
}

CK_RV
p11c_return_data_as_hex_string(CK_ATTRIBUTE_PTR attr, CK_VOID_PTR data, CK_ULONG length)
{
	CK_ULONG i;

	/* Allow 2 characters per byte. PKCS#11 strings are not null-terminated. */
	const CK_ULONG string_length = length * 2;

	/* Just asking for the length */
	if(!attr->pValue)
	{
		attr->ulValueLen = string_length;
		return CKR_OK;
	}

	/* Buffer is too short */
	if(attr->ulValueLen < string_length)
	{
		attr->ulValueLen = string_length;
		return CKR_BUFFER_TOO_SMALL;
	}

	/* Convert to hex string, discarding null terminators */
	for(i = 0; i < length; ++i)
	{
		unsigned char* bytes = data;
		unsigned char* value = attr->pValue;
		char buf[3];

		snprintf(buf, sizeof(buf), "%02x", bytes[i]);
		memcpy(&value[i * 2], buf, sizeof(buf) - 1);
	}

	return CKR_OK;
}

CK_RV
p11c_return_dword_as_bytes(CK_ATTRIBUTE_PTR attr, DWORD value)
{
	int i;
	CK_ULONG count = 0;
	BOOL first = TRUE;
	BYTE* at = attr->pValue;
	CK_RV ret = CKR_OK;

	for(i = 0; i < sizeof(DWORD); i++) 
	{
		BYTE digit = (BYTE)((value >> (((sizeof(DWORD)-1)*8))) & 0xFF);
		value = value << 8;

		/* No leading zero */
		if (first && digit == 0)
			continue;

		first = FALSE;
		if(at)
		{
			if(count > attr->ulValueLen)
				ret = CKR_BUFFER_TOO_SMALL;
			else
				*(at++) = digit;
		}

		count++;
	}

	attr->ulValueLen = count;
	return ret;
}

CK_RV
p11c_return_reversed_data(CK_ATTRIBUTE_PTR attr, CK_VOID_PTR data, CK_ULONG length)
{
	CK_RV ret = p11c_return_data(attr, data, length);
	if(ret != CKR_OK || !attr->pValue)
		return ret;

	p11c_reverse_memory(attr->pValue, attr->ulValueLen);
	return CKR_OK;
}

static void
print_zero_decimal(CK_BYTE_PTR buffer, CK_ULONG length, WORD value)
{
	int i;
	for(i = (int)length - 1; i >= 0; --i)
	{
		BYTE digit = value % 10;
		buffer[i] = '0' + digit;
		value /= 10;
	}
}

CK_RV
p11c_return_filetime(CK_ATTRIBUTE_PTR attr, FILETIME *ftime)
{
	SYSTEMTIME stime;
	CK_DATE* date;

	ASSERT(attr);
	ASSERT(ftime);

	if(!attr->pValue)
	{
		attr->ulValueLen = sizeof(CK_DATE);
		return CKR_OK;
	}

	if(attr->ulValueLen < sizeof(CK_DATE))
	{
		attr->ulValueLen = sizeof(CK_DATE);
		return CKR_BUFFER_TOO_SMALL;
	}

	if(!FileTimeToSystemTime(ftime, &stime))
	{
		WARN(("An invalid FILETIME was encountered"));
                p11c_log("An invalid FILETIME was encountered");
		return CKR_GENERAL_ERROR;
	}

	date = (CK_DATE*)attr->pValue;
	attr->ulValueLen = sizeof(CK_DATE);
	print_zero_decimal(date->year, sizeof(date->year), stime.wYear);
	print_zero_decimal(date->month, sizeof(date->month), stime.wMonth);
	print_zero_decimal(date->day, sizeof(date->day), stime.wDay);

	return CKR_OK;
}

/* ---------------------------------------------------------------- */

static CK_RV
PC_C_Initialize(CK_VOID_PTR init_args)
{
	ENTER(C_Initialize);
	PREREQ(!cryptoki_initialized, CKR_CRYPTOKI_ALREADY_INITIALIZED);

	if (init_args != NULL) {
		CK_C_INITIALIZE_ARGS_PTR args;
		int supplied_ok;

		/* pReserved must be NULL */
		args = init_args;
		PREREQ(!args->pReserved, CKR_ARGUMENTS_BAD);

		/* ALL supplied function pointers need to have the value either NULL or non-NULL. */
		supplied_ok = (args->CreateMutex == NULL && args->DestroyMutex == NULL &&
		               args->LockMutex == NULL && args->UnlockMutex == NULL) ||
		              (args->CreateMutex != NULL && args->DestroyMutex != NULL &&
		               args->LockMutex != NULL && args->UnlockMutex != NULL);
		PREREQ(supplied_ok, CKR_ARGUMENTS_BAD);

		/*
		 * When the CKF_OS_LOCKING_OK flag isn't set and mutex function pointers are supplied
		 * by an application, return an error. We must be able to use our own locks.
		 */
		if(!(args->flags & CKF_OS_LOCKING_OK) && (args->CreateMutex != NULL)) 
			RETURN(CKR_CANT_LOCK);
	}

	if(!global_mutex)
	{
		global_mutex = CreateMutex(NULL, FALSE, NULL);
		if(!global_mutex)
			RETURN(CKR_CANT_LOCK);
	}

	cryptoki_initialized = 1;
#ifdef FILE_LOGGING
        output_file = fopen ("log.txt", "ab");
        if (!output_file) {
          output_file = stderr;
        }
#endif
	p11c_log("initialized p11-capi module");
	RETURN(CKR_OK);
}

static CK_RV
PC_C_Finalize(CK_VOID_PTR pReserved)
{
	ENTER(C_Finalize);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(!pReserved, CKR_ARGUMENTS_BAD);

	cryptoki_initialized = 0;

	p11c_session_cleanup_all();
	p11c_token_cleanup_all();

	p11c_log("finalized p11-capi module");
	RETURN(CKR_OK);
}

static CK_RV
PC_C_GetInfo(CK_INFO_PTR info)
{
	ENTER(C_GetInfo);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(info, CKR_ARGUMENTS_BAD);
	
	ASSERT(strlen(MANUFACTURER_ID) == 32);
	ASSERT(strlen(LIBRARY_DESCRIPTION) == 32);

	info->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	info->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	info->libraryVersion.major = LIBRARY_VERSION_MAJOR;
	info->libraryVersion.minor = LIBRARY_VERSION_MINOR;
	info->flags = 0;
	strncpy((char*)info->manufacturerID, MANUFACTURER_ID, 32);
	strncpy((char*)info->libraryDescription, LIBRARY_DESCRIPTION, 32);

	RETURN(CKR_OK);
}

static CK_RV
PC_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list)
{
	/* This would be a strange call to receive */
	return C_GetFunctionList(list);
}

static CK_RV
PC_C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR count)
{
	unsigned int n_tokens, i;

	ENTER(C_GetSlotList);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(count, CKR_ARGUMENTS_BAD);
	
	/* All tokens are always present */

	n_tokens = p11c_token_get_count();

	/* Application only wants to know the number of slots. */
	if(slot_list == NULL) 
	{
		*count = n_tokens;
		RETURN(CKR_OK);
	}

	if(*count < n_tokens) 
	{
		*count = n_tokens;
		RETURN(CKR_BUFFER_TOO_SMALL);
	}
		
	*count = n_tokens;
	for(i = 0; i < n_tokens; ++i)
		slot_list[i] = p11c_token_get_slot_id (i);
	RETURN(CKR_OK);
}

static CK_RV
PC_C_GetSlotInfo(CK_SLOT_ID id, CK_SLOT_INFO_PTR info)
{
	const char* name;

	ENTER(C_GetSlotInfo);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(info, CKR_ARGUMENTS_BAD);

	/* Make sure the slot ID is valid */
	if(!p11c_token_is_valid(id))
		RETURN(CKR_SLOT_ID_INVALID);

	ASSERT(strlen(MANUFACTURER_ID) == 32);

	/* Provide information about the slot in the provided buffer */
	strncpy((char*)info->manufacturerID, MANUFACTURER_ID, 32);
	info->hardwareVersion.major = HARDWARE_VERSION_MAJOR;
	info->hardwareVersion.minor = HARDWARE_VERSION_MINOR;
	info->firmwareVersion.major = FIRMWARE_VERSION_MAJOR;
	info->firmwareVersion.minor = FIRMWARE_VERSION_MINOR;

	/* Token is always present */
	info->flags = CKF_TOKEN_PRESENT;

	/* Slot name is blank padded, odd */
	name = p11c_token_get_display_name(id);
	memset((char*)info->slotDescription, ' ', 
	       sizeof(info->slotDescription));
	memcpy((char*)info->slotDescription, name, 
		   min(strlen(name), sizeof(info->slotDescription)));

	RETURN(CKR_OK);
}

static CK_RV
PC_C_GetTokenInfo(CK_SLOT_ID id, CK_TOKEN_INFO_PTR info)
{
	const char* name;

	ENTER(C_GetTokenInfo);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(info, CKR_ARGUMENTS_BAD);

	/* Make sure the slot ID is valid */
	if(!p11c_token_is_valid(id)) 
		RETURN(CKR_SLOT_ID_INVALID);
		
	ASSERT(strlen(MANUFACTURER_ID) == 32);
	ASSERT(strlen(SLOT_TOKEN_MODEL) == 16);
	ASSERT(strlen(SLOT_TOKEN_SERIAL) == 16);

	/* Provide information about a token in the provided buffer */
	strncpy((char*)info->manufacturerID, MANUFACTURER_ID, 32);
	strncpy((char*)info->model, SLOT_TOKEN_MODEL, 16);
	strncpy((char*)info->serialNumber, SLOT_TOKEN_SERIAL, 16);

	/* Protected authentication path: Windows prompts for it's own PINs */
	info->flags = CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH;
	info->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulRwSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulMaxPinLen = MAX_PIN_LEN;
	info->ulMinPinLen = MIN_PIN_LEN;
	info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->hardwareVersion.major = HARDWARE_VERSION_MAJOR;
	info->hardwareVersion.minor = HARDWARE_VERSION_MINOR;
	info->firmwareVersion.major = FIRMWARE_VERSION_MAJOR;
	info->firmwareVersion.minor = FIRMWARE_VERSION_MINOR;
	memset(info->utcTime, ' ', 16);

	/* Slot name is blank padded, odd */
	name = p11c_token_get_display_name(id);
	memset((char*)info->label, ' ', sizeof(info->label));
	memcpy((char*)info->label, name, 
		   min(strlen(name), sizeof(info->label)));

	RETURN(CKR_OK);
}

static CK_RV
PC_C_GetMechanismList(CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR mechanism_list,
                      CK_ULONG_PTR count)
{
	CK_ULONG n_mechs;

	ENTER(C_GetMechanismList);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(count, CKR_ARGUMENTS_BAD);

	if(!p11c_token_is_valid(id))
		RETURN(CKR_SLOT_ID_INVALID);

	n_mechs = sizeof(all_mechanisms) / sizeof(all_mechanisms[0]);

	if(mechanism_list == NULL) 
	{
		*count = n_mechs;
		RETURN(CKR_OK);
	}

	if(*count < n_mechs) 
	{
		*count = n_mechs;
		RETURN(CKR_BUFFER_TOO_SMALL);
	}

	memcpy(mechanism_list, all_mechanisms, 
	       n_mechs * sizeof(CK_MECHANISM_TYPE));
	*count = n_mechs;
	RETURN(CKR_OK);
}

static CK_RV
PC_C_GetMechanismInfo(CK_SLOT_ID id, CK_MECHANISM_TYPE type, 
                      CK_MECHANISM_INFO_PTR info)
{
	ENTER(C_GetMechanismInfo);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(info, CKR_ARGUMENTS_BAD);

	if(!p11c_token_is_valid(id)) 
		RETURN(CKR_SLOT_ID_INVALID);

	if(type == CKM_RSA_PKCS)
	{
		p11c_rsa_pkcs_get_info(type, info);
		RETURN(CKR_OK);
	}

	RETURN(CKR_MECHANISM_INVALID);
}

static CK_RV
PC_C_InitToken(CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len, 
               CK_UTF8CHAR_PTR label)
{
	ENTER(C_InitToken);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	ENTER(C_WaitForSlotEvent);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	
	/* 
	 * PKCS#11 GRAY AREA: What happens when we know we'll *never* 
	 * have any slot events, and someone calls us without CKR_DONT_BLOCK?
	 * In case there's a thread dedicated to calling this function in a 
	 * loop, we wait 1 seconds when called without CKR_DONT_BLOCK.
	 */
	
	if(!(flags & CKF_DONT_BLOCK))
		Sleep(1000);
	
	RETURN(CKR_NO_EVENT);
}

static CK_RV
PC_C_OpenSession(CK_SLOT_ID id, CK_FLAGS flags, CK_VOID_PTR application,
                 CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session)
{
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_OpenSession);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(session, CKR_ARGUMENTS_BAD);
	PREREQ(flags & CKF_SERIAL_SESSION, CKR_SESSION_PARALLEL_NOT_SUPPORTED);

	if(!p11c_token_is_valid(id)) 
		RETURN(CKR_SLOT_ID_INVALID);

	ret = p11c_session_create(id, &sess);
	if(ret != CKR_OK)
		RETURN(ret);

	sess->notify_callback = notify;
	sess->user_data = application;

	if(flags & CKF_RW_SESSION)
		sess->read_write = TRUE;

	ret = p11c_session_register(sess);
	if(ret == CKR_OK)
	{
		/* ID should have been assigned when registering */
		ASSERT(sess->id > 0);
		*session = sess->id;
	}
	else
	{
		p11c_session_destroy(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_CloseSession(CK_SESSION_HANDLE session)
{
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_CloseSession);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	ret = p11c_session_remove_lock_ref(session, &sess);
	if(ret == CKR_OK)
	{
		/* This will unref and possibly destroy the session */
		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_CloseAllSessions(CK_SLOT_ID id)
{
	ENTER(C_CloseAllSession);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	if(!p11c_token_is_valid(id)) 
		RETURN(CKR_SLOT_ID_INVALID);

	p11c_session_close_all(id);
	RETURN(CKR_OK);
}

static CK_RV
PC_C_GetFunctionStatus(CK_SESSION_HANDLE session)
{
	ENTER(C_GetFunctionStatus);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	RETURN(CKR_FUNCTION_NOT_PARALLEL);
}

static CK_RV
PC_C_CancelFunction(CK_SESSION_HANDLE session)
{
	ENTER(C_CancelFunction);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	RETURN(CKR_FUNCTION_NOT_PARALLEL);
}

static CK_RV
PC_C_GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO_PTR info)
{
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_GetSessionInfo);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(info, CKR_ARGUMENTS_BAD);

	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		p11c_session_get_info(sess, info);
		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_InitPIN(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin, 
              CK_ULONG pin_len)
{
	ENTER(C_InitPIN);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* We don't support this stuff. We don't support 'SO' logins. */
	RETURN(CKR_USER_NOT_LOGGED_IN);
}

static CK_RV
PC_C_SetPIN(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR old_pin,
             CK_ULONG old_len, CK_UTF8CHAR_PTR new_pin, CK_ULONG new_len)
{
	ENTER(C_SetPIN);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Not supported, Windows takes care of this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_GetOperationState(CK_SESSION_HANDLE session, CK_BYTE_PTR operation_state,
                       CK_ULONG_PTR operation_state_len)
{
	ENTER(C_GetOperationState);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Nasty, no sirrr  */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_SetOperationState(CK_SESSION_HANDLE session, CK_BYTE_PTR operation_state,
                       CK_ULONG operation_state_len, CK_OBJECT_HANDLE encryption_key,
                       CK_OBJECT_HANDLE authentication_key)
{
	ENTER(C_SetOperationState);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Nasty, no sirrr  */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_Login(CK_SESSION_HANDLE session, CK_USER_TYPE user_type,
           CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_Login);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	
	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		switch(user_type)
		{
		case CKU_USER:
			ret = p11c_token_login(sess->slot);
			break;
		case CKU_SO:
			ret = CKR_USER_TYPE_INVALID;
			break;
		default:
			ret = CKR_USER_TYPE_INVALID;
			break;
		}

		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_Logout(CK_SESSION_HANDLE session)
{
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_Logout);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		ret = p11c_token_logout(sess->slot);
		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_CreateObject(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR templ,
                  CK_ULONG count, CK_OBJECT_HANDLE_PTR object)
{
	ENTER(C_CreateObject);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to support this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_CopyObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                CK_ATTRIBUTE_PTR templ, CK_ULONG count,
                CK_OBJECT_HANDLE_PTR new_object)
{
	ENTER(C_CopyObject);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to support this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}


static CK_RV
PC_C_DestroyObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
	ENTER(C_DestroyObject);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to support this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_GetObjectSize(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                   CK_ULONG_PTR size)
{
	ENTER(C_GetObjectSize);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: Implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_GetAttributeValue(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                       CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	P11cSession* sess;
	P11cObjectData* objdata;
	CK_RV ret;

	ENTER(C_GetAttributeValue);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(object, CKR_OBJECT_HANDLE_INVALID);
	PREREQ(!count || templ, CKR_ARGUMENTS_BAD);
	
	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		ret = p11c_session_get_object_data_for(sess, object, &objdata);
		if(ret == CKR_OK)
			ret = p11c_object_data_get_attrs(objdata, templ, count);

		p11c_session_unref_unlock(sess);
	}

	if(ret == CKR_OBJECT_HANDLE_INVALID)
	{
		WARN(("object handle invalid"));
	}

	RETURN(ret);
}

static CK_RV
PC_C_SetAttributeValue(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                       CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	ENTER(C_SetAttributeValue);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_FindObjectsInit(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR templ,
                     CK_ULONG count)
{
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_FindObjectsInit);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(!count || templ, CKR_ARGUMENTS_BAD);

	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		ret = p11c_session_find_init(sess, templ, count);
		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_FindObjects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR objects,
                 CK_ULONG max_object_count, CK_ULONG_PTR object_count)
{
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_FindObjects);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(object_count, CKR_ARGUMENTS_BAD);
	PREREQ(!max_object_count || objects, CKR_ARGUMENTS_BAD);

	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		ret = p11c_session_find(sess, objects, max_object_count, object_count);
		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_FindObjectsFinal(CK_SESSION_HANDLE session)
{
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_FindObjectsFinal);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		ret = p11c_session_find_final(sess);
		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_EncryptInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE key)
{
	ENTER(C_EncryptInit);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_Encrypt(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len,
             CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len)
{
	ENTER(C_Encrypt);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_EncryptUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR part,
                   CK_ULONG part_len, CK_BYTE_PTR encrypted_part,
                   CK_ULONG_PTR encrypted_part_len)
{
	ENTER(C_EncryptUpdate);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_EncryptFinal(CK_SESSION_HANDLE session, CK_BYTE_PTR last_encrypted_part,
                  CK_ULONG_PTR last_encrypted_part_len)
{
	ENTER(C_EncryptFinal);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_DecryptInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE key)
{
	P11cObjectData* objdata;
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_DecryptInit);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(mechanism, CKR_ARGUMENTS_BAD);
	PREREQ(key, CKR_ARGUMENTS_BAD);

	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		ret = p11c_session_get_object_data_for(sess, key, &objdata);
		if(ret == CKR_OK)
			ret = p11c_session_decrypt_init(sess, mechanism, objdata);

		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_Decrypt(CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_data,
             CK_ULONG encrypted_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_Decrypt);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(encrypted_data, CKR_ARGUMENTS_BAD);
	PREREQ(encrypted_data_len, CKR_ARGUMENTS_BAD);

	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		ret = p11c_session_decrypt(sess, encrypted_data, encrypted_data_len, 
		                             data, data_len);
		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_DecryptUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_part,
                   CK_ULONG encrypted_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len)
{
	ENTER(C_DecryptUpdate);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_DecryptFinal(CK_SESSION_HANDLE session, CK_BYTE_PTR pLastPart,
                  CK_ULONG_PTR last_part_len)
{
	ENTER(C_DecryptFinal);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_DigestInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism)
{
	ENTER(C_DigestInit);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support digest. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_Digest(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len,
            CK_BYTE_PTR digest, CK_ULONG_PTR digest_len)
{
	ENTER(C_Digest);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support digest. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_DigestUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len)
{
	ENTER(C_DigestUpdate);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support digest. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_DigestKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	ENTER(C_DigestKey);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support digest. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_DigestFinal(CK_SESSION_HANDLE session, CK_BYTE_PTR digest,
                 CK_ULONG_PTR digest_len)
{
	ENTER(C_DigestFinal);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support digest. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_SignInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
              CK_OBJECT_HANDLE key)
{
	P11cObjectData* objdata;
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_SignInit);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(mechanism, CKR_ARGUMENTS_BAD);
	PREREQ(key, CKR_ARGUMENTS_BAD);

	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		ret = p11c_session_get_object_data_for(sess, key, &objdata);
		if(ret == CKR_OK)
			ret = p11c_session_sign_init(sess, mechanism, objdata);

		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_Sign(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len,
          CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	P11cSession* sess;
	CK_RV ret;

	ENTER(C_Sign);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ(data, CKR_ARGUMENTS_BAD);
	PREREQ(data_len, CKR_ARGUMENTS_BAD);

	ret = p11c_session_get_lock_ref(session, FALSE, &sess);
	if(ret == CKR_OK)
	{
		ret = p11c_session_sign(sess, data, data_len, signature, signature_len);
		p11c_session_unref_unlock(sess);
	}

	RETURN(ret);
}

static CK_RV
PC_C_SignUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len)
{
	ENTER(C_SignUpdate);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_SignFinal(CK_SESSION_HANDLE session, CK_BYTE_PTR signature,
               CK_ULONG_PTR signature_len)
{
	ENTER(C_SignFinal);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_SignRecoverInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                     CK_OBJECT_HANDLE key)
{
	ENTER(C_SignRecoverInit);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: Implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_SignRecover(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, 
                 CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	ENTER(C_SignRecover);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: Implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_VerifyInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                CK_OBJECT_HANDLE key)
{
	ENTER(C_VerifyInit);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_Verify(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len,
            CK_BYTE_PTR signature, CK_ULONG signature_len)
{
	ENTER(C_Verify);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_VerifyUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len)
{
	ENTER(C_VerifyUpdate);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_VerifyFinal(CK_SESSION_HANDLE session, CK_BYTE_PTR signature,
                 CK_ULONG signature_len)
{
	ENTER(C_VerifyFinal);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_VerifyRecoverInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                       CK_OBJECT_HANDLE key)
{
	ENTER(C_VerifyRecoverInit);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_VerifyRecover(CK_SESSION_HANDLE session, CK_BYTE_PTR signature,
                   CK_ULONG signature_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	ENTER(C_VerifyRecover);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_DigestEncryptUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR part,
                         CK_ULONG part_len, CK_BYTE_PTR encrypted_part,
                         CK_ULONG_PTR encrypted_part_len)
{
	ENTER(C_DigestEncryptUpdate);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_DecryptDigestUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_part,
                         CK_ULONG encrypted_part_len, CK_BYTE_PTR part, 
                         CK_ULONG_PTR part_len)
{
	ENTER(C_DecryptDigestUpdate);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_SignEncryptUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR part,
                       CK_ULONG part_len, CK_BYTE_PTR encrypted_part,
                       CK_ULONG_PTR encrypted_part_len)
{
	ENTER(C_SignEncryptUpdate);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_DecryptVerifyUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR encrypted_part,
                         CK_ULONG encrypted_part_len, CK_BYTE_PTR part, 
                         CK_ULONG_PTR part_len)
{
	ENTER(C_DecryptVerifyUpdate);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* RSA/DSA mechs don't support incremental crypto operations. */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_GenerateKey(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                 CK_ATTRIBUTE_PTR templ, CK_ULONG count, 
                 CK_OBJECT_HANDLE_PTR key)
{
	ENTER(C_GenerateKey);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Let key generation happen via Windows interfaces */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_GenerateKeyPair(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                     CK_ATTRIBUTE_PTR public_key_template, CK_ULONG public_key_attribute_count,
                     CK_ATTRIBUTE_PTR private_key_template, CK_ULONG private_key_attribute_count,
                     CK_OBJECT_HANDLE_PTR public_key, CK_OBJECT_HANDLE_PTR private_key)
{
	ENTER(C_GenerateKeyPair);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Let key generation happen via Windows interfaces */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_WrapKey(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
             CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
             CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len)
{
	ENTER(C_WrapKey);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_UnwrapKey(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
               CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key,
               CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR templ,
               CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	ENTER(C_UnwrapKey);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* TODO: See if we need to implement this */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_DeriveKey(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
               CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE_PTR templ,
               CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	ENTER(C_DeriveKey);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Can't do this with RSA */
	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_SeedRandom(CK_SESSION_HANDLE session, CK_BYTE_PTR seed, CK_ULONG seed_len)
{
	ENTER(C_SeedRandom);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * TODO: Perhaps at some point in the future we may want 
	 * to see if we can hook into the Windows RNG 
	 */

	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
PC_C_GenerateRandom(CK_SESSION_HANDLE session, CK_BYTE_PTR random_data,
                    CK_ULONG random_len)
{
	ENTER(C_GenerateRandom);
	PREREQ(cryptoki_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * TODO: Perhaps at some point in the future we may want 
	 * to see if we can hook into the Windows RNG 
	 */

	RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_FUNCTION_LIST functionList = {
	{ 2, 11 },	/* version */
	PC_C_Initialize,
	PC_C_Finalize,
	PC_C_GetInfo,
	PC_C_GetFunctionList,
	PC_C_GetSlotList,
	PC_C_GetSlotInfo,
	PC_C_GetTokenInfo,
	PC_C_GetMechanismList,
	PC_C_GetMechanismInfo,
	PC_C_InitToken,
	PC_C_InitPIN,
	PC_C_SetPIN,
	PC_C_OpenSession,
	PC_C_CloseSession,
	PC_C_CloseAllSessions,
	PC_C_GetSessionInfo,
	PC_C_GetOperationState,
	PC_C_SetOperationState,
	PC_C_Login,
	PC_C_Logout,
	PC_C_CreateObject,
	PC_C_CopyObject,
	PC_C_DestroyObject,
	PC_C_GetObjectSize,
	PC_C_GetAttributeValue,
	PC_C_SetAttributeValue,
	PC_C_FindObjectsInit,
	PC_C_FindObjects,
	PC_C_FindObjectsFinal,
	PC_C_EncryptInit,
	PC_C_Encrypt,
	PC_C_EncryptUpdate,
	PC_C_EncryptFinal,
	PC_C_DecryptInit,
	PC_C_Decrypt,
	PC_C_DecryptUpdate,
	PC_C_DecryptFinal,
	PC_C_DigestInit,
	PC_C_Digest,
	PC_C_DigestUpdate,
	PC_C_DigestKey,
	PC_C_DigestFinal,
	PC_C_SignInit,
	PC_C_Sign,
	PC_C_SignUpdate,
	PC_C_SignFinal,
	PC_C_SignRecoverInit,
	PC_C_SignRecover,
	PC_C_VerifyInit,
	PC_C_Verify,
	PC_C_VerifyUpdate,
	PC_C_VerifyFinal,
	PC_C_VerifyRecoverInit,
	PC_C_VerifyRecover,
	PC_C_DigestEncryptUpdate,
	PC_C_DecryptDigestUpdate,
	PC_C_SignEncryptUpdate,
	PC_C_DecryptVerifyUpdate,
	PC_C_GenerateKey,
	PC_C_GenerateKeyPair,
	PC_C_WrapKey,
	PC_C_UnwrapKey,
	PC_C_DeriveKey,
	PC_C_SeedRandom,
	PC_C_GenerateRandom,
	PC_C_GetFunctionStatus,
	PC_C_CancelFunction,
	PC_C_WaitForSlotEvent
};

__declspec(dllexport) CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list)
{
	if(!list)
		return CKR_ARGUMENTS_BAD;

	*list = &functionList;
	return CKR_OK;
}

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

#ifndef P11C_H
#define P11C_H

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

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x400
#include <windows.h>
#include <wincrypt.h>

#define P11c_ENCODINGS	(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

#define CRYPTOKI_EXPORTS
#include "pkcs11/pkcs11.h"

#include "p11-capi-util.h"

struct _P11cSlot;
struct _P11cObject;
struct _P11cObjectData;
struct _P11cSession;

typedef struct _P11cSlot P11cSlot;
typedef struct _P11cObject P11cObject;
typedef struct _P11cObjectData P11cObjectData;
typedef struct _P11cSession P11cSession;

/* ------------------------------------------------------------------
 * cryptoki-capi.c
 * 
 * Module helper and logging functions.
 */

#define DBG_OUTPUT 1
#if DBG_OUTPUT
#define     DBG(args)                     p11c_log args
#else
#define		DBG(args)                     
#endif

#define     WARN(args)                    p11c_log args

void        p11c_log                      (const char* msg, ...);

/* 
 * Protect global data with these.
 */
void        p11c_lock_global              (void);
void        p11c_unlock_global            (void);

/*
 * Convert a GetLastError() windows error to a 
 * PKCS#11 return code. 
 */
CK_RV       p11c_winerr_to_ckr            (DWORD werr);

/* 
 * This stores data in the output buffer with appropriate 
 * PKCS#11 codes when the buffer is too short, or the caller
 * just wants to know the length, etc.
 */
CK_RV       p11c_return_data              (CK_ATTRIBUTE_PTR attr, 
                                           CK_VOID_PTR src, DWORD slen);

CK_RV       p11c_return_data_raw          (CK_VOID_PTR output, CK_ULONG_PTR n_output,
                                           CK_VOID_PTR input, CK_ULONG n_input);

/*
 * This stores a string in the output buffer with appropriate
 * PKCS#11 codes when the buffer is too short, or the caller
 * just wants to know the length, etc.
 */
CK_RV       p11c_return_string            (CK_ATTRIBUTE_PTR attr, 
                                           WCHAR* string);

CK_RV       p11c_return_data_as_hex_string(CK_ATTRIBUTE_PTR attr,
                                           CK_VOID_PTR data, CK_ULONG length);

CK_RV       p11c_return_dword_as_bytes    (CK_ATTRIBUTE_PTR attr, 
                                           DWORD value);

CK_RV       p11c_return_reversed_data     (CK_ATTRIBUTE_PTR attr, 
                                           CK_VOID_PTR data, CK_ULONG length);

CK_RV       p11c_return_filetime          (CK_ATTRIBUTE_PTR attr, 
                                           FILETIME* ftime);

/* ------------------------------------------------------------------ */

typedef void (*P11cDestroyFunc)(void* data);

#ifndef ASSERT
#include "assert.h"
#define ASSERT assert
#endif

/* Represents 'any' class in searches */
#define CKO_ANY CK_INVALID_HANDLE


#endif /* P11C_CAPI_H */

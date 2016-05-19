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

#ifndef P11C_TOKEN_H
#define P11C_TOKEN_H

#include "p11-capi.h"

#define     P11C_SLOT_CERTS     0x00000001
#define     P11C_SLOT_ANYKEY    0x00000002
#define     P11C_SLOT_CA        0x00000100
#define     P11C_SLOT_TRUSTED   0x00000200

/* Register a new object, a handle will be assigned to obj->id */
CK_RV               p11c_token_register_object       (CK_SLOT_ID slot, P11cObject* obj);

/* Lookup an object for a given object handle */
P11cObject*         p11c_token_lookup_object         (CK_SLOT_ID slot, CK_OBJECT_HANDLE obj);

/* Clear all objects for all tokens. Only done when finalizing */
void                p11c_token_cleanup_all           (void);

/* Get the number of the maximum object handle currently in memory */
CK_OBJECT_HANDLE    p11c_token_get_max_handle        (void);

unsigned int        p11c_token_get_count             (void);

CK_SLOT_ID          p11c_token_get_slot_id           (unsigned int index);

CK_BBOOL            p11c_token_is_valid              (CK_SLOT_ID slot);

const char*         p11c_token_get_display_name      (CK_SLOT_ID slot);

const char*         p11c_token_get_store_name        (CK_SLOT_ID slot);

CK_ULONG            p11c_token_get_flags             (CK_SLOT_ID slot);

CK_RV               p11c_token_login                 (CK_SLOT_ID slot);

CK_RV               p11c_token_logout                (CK_SLOT_ID slot);

CK_BBOOL            p11c_token_is_logged_in          (CK_SLOT_ID slot);

#endif /* P11C_TOKEN_H */

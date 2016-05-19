/* 
 * Copyright (C) 2008 Stef Walter
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

#ifndef P11C_RSA_H
#define P11C_RSA_H

#include "p11-capi.h"

CK_RV      p11c_rsa_pkcs_sign_init        (P11cObjectData* keydata, void** operation);

CK_RV      p11c_rsa_pkcs_sign_perform     (CK_BYTE_PTR data, CK_ULONG data_len,
                                           CK_BYTE_PTR signature, CK_ULONG_PTR signature_len,
                                           void** operation);

void       p11c_rsa_pkcs_sign_cleanup     (void* operation);

CK_RV      p11c_rsa_pkcs_decrypt_init     (P11cObjectData* keydata, void** operation);

CK_RV      p11c_rsa_pkcs_decrypt_perform  (CK_BYTE_PTR encdata, CK_ULONG n_encdata,
                                           CK_BYTE_PTR result, CK_ULONG_PTR n_result,
                                           void** operation);

void       p11c_rsa_pkcs_decrypt_cleanup  (void* operation);

void       p11c_rsa_pkcs_get_info         (CK_MECHANISM_TYPE mech, 
                                           CK_MECHANISM_INFO_PTR info);

#endif /* P11C_RSA_H */

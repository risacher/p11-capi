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

#ifndef P11C_DER_H
#define P11C_DER_H

#include "p11-capi.h"

#define P11C_DER_OCTET_STRING        0x04
#define P11C_DER_OBJECT_ID           0x06
#define P11C_DER_SEQUENCE            0x10
#define P11C_DER_CONSTRUCTED         0x20

BYTE*    p11c_der_unwrap      (BYTE* src, DWORD n_src, 
                               DWORD* n_result, BYTE** next);

char*    p11c_der_read_oid    (BYTE* oid_tag, DWORD n_oid_tag);

#endif /* P11C_DER_H */

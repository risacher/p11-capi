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

#ifndef P11C_TRUST_H
#define P11C_TRUST_H

#include "p11-capi.h"

/* Find trust objects matching criteria */
CK_RV               p11c_trust_find                (P11cSession* sess, CK_OBJECT_CLASS cls, 
                                                    CK_ATTRIBUTE_PTR match, CK_ULONG count, 
                                                    P11cArray* arr);

#endif /* P11C_TRUST_H */

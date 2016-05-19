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

#ifndef P11C_CERT_H
#define P11C_CERT_H

#include "p11-capi.h"
#include "p11-capi-util.h"

/* Find certificates matching criteria */
CK_RV           p11c_cert_find                         (P11cSession* sess, CK_OBJECT_CLASS cls, 
                                                        CK_ATTRIBUTE_PTR match,  CK_ULONG count, 
                                                        P11cArray* arr);

/* Called by trust and key stuff */
CK_RV           p11c_cert_certificate_get_bytes        (PCCERT_CONTEXT cert, 
                                                        CK_ATTRIBUTE_PTR attr);

PCCERT_CONTEXT  p11c_cert_object_data_get_certificate  (P11cObjectData* objdata);

#endif /* P11C_CERT_H */

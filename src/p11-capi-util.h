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

#ifndef __P11C_UTIL_H__
#define __P11C_UTIL_H__

#include <stdlib.h>


void            p11c_reverse_memory        (void* data, size_t length);

/* --------------------------------------------------------------------------------
 * ARRAYS
 */

typedef struct _Array
{
	void* data;
	size_t len;
}
P11cArray;

#define         p11c_array_append(a,v)      p11c_array_append_vals(a, &(v), 1)
#define         p11c_array_index(a,t,i)     (((t*) (a)->data) [(i)])

P11cArray*      p11c_array_new              (int zero_terminated, int zero, 
                                             size_t element_size);
	
P11cArray*      p11c_array_sized_new        (int zero_terminated, int zero, 
                                             size_t element_size, size_t reserved_size);

void*           p11c_array_free	            (P11cArray* array, int free_segment);

int             p11c_array_append_vals      (P11cArray* array, const void* data,
                                             size_t num);

void            p11c_array_remove_index     (P11cArray* array, unsigned int index);

void            p11c_array_remove_range     (P11cArray* array, unsigned int index, 
                                             size_t count);


/* --------------------------------------------------------------------------------
 * HASHTABLE
 */

struct _P11cHash;
typedef struct _P11cHash P11cHash;

typedef unsigned int (*P11cHashFunc)(const void* key);

typedef int  (*P11cHashEqual)(const void* a, const void* b);

typedef void (*P11cHashDestroy)(void* val);

P11cHash*    p11c_hash_new        (P11cHashFunc hash_func, P11cHashEqual equal_func);

void         p11c_hash_free       (P11cHash* ht, P11cHashDestroy destroy_func);

size_t       p11c_hash_count      (P11cHash* ht);

void*        p11c_hash_get        (P11cHash* ht, const void* key);

int          p11c_hash_set        (P11cHash* ht, const void* key, void* val);

void*		 p11c_hash_rem        (P11cHash* ht, const void* key);

unsigned int p11c_hash_pointer    (const void* ptr);

unsigned int p11c_hash_data       (const void* data, size_t n_data);

unsigned int p11c_hash_integer    (int integer);

#define      p11c_hash_key(num)   (((char*)NULL) + (size_t)(num))

#endif /* __P11C_UTIL_H__ */

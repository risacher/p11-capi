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

#include "p11-capi-util.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>


void
p11c_reverse_memory (void* data, size_t length)
{
	size_t end = length - 1;
	size_t middle = length / 2;
	unsigned char* buf = data;
	size_t i;

	for (i = 0; i < middle; i++) 
	{
		unsigned char tmp = buf[i];
		buf[i] = buf[end - i];
		buf[end - i] = tmp;
	}
}

/* 
 * Array code originially from Glib. 
 * Modified extensively by Stef Walter <nielsen@memberwebs.com>
 */

/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
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


#define MIN_ARRAY_SIZE  16

typedef struct _RealArray
{
	P11cArray pub;
	size_t alloc;
	size_t elt_size;
	int zero_terminated : 1;
	int clear : 1;
}
RealArray;

#define array_elt_len(array, i) ((array)->elt_size * (i))
#define array_elt_pos(array, i) (((char*)(array)->pub.data) + array_elt_len((array),(i)))
#define array_elt_zero(array, pos, len) \
	(memset(array_elt_pos((array), pos), 0, array_elt_len((array), len)))
#define array_zero_terminate(array) \
	{ if ((array)->zero_terminated) \
		array_elt_zero((array), (array)->pub.len, 1); }

static unsigned int
nearest_pow(unsigned int num)
{
	unsigned int n = 1;
	while(n < num)
		n <<= 1;
	return n;
}

static int
maybe_expand(RealArray *array, size_t len)
{
	void* mem;
	size_t want_alloc = array_elt_len(array, array->pub.len + len + 
	                                  array->zero_terminated);

	if(want_alloc > array->alloc)
	{
		want_alloc = nearest_pow(want_alloc);
		want_alloc = want_alloc > MIN_ARRAY_SIZE ? want_alloc : MIN_ARRAY_SIZE;

		mem = realloc(array->pub.data, want_alloc);
		if(!mem)
			return 0;
		array->pub.data = mem;

		memset((char*)array->pub.data + array->alloc, 0, want_alloc - array->alloc);
		array->alloc = want_alloc;
	}

	return 1;
}

P11cArray*
p11c_array_new(int zero_terminated, int clear, size_t elt_size)
{
	return p11c_array_sized_new(zero_terminated, clear, elt_size, 0);
}

P11cArray* 
p11c_array_sized_new(int zero_terminated, int clear, size_t elt_size,
                     size_t reserved_size)
{
	RealArray *array = malloc(sizeof(RealArray));
	if(!array)
		return NULL;

	array->pub.data        = NULL;
	array->pub.len         = 0;
	array->alloc           = 0;
	array->zero_terminated = (zero_terminated ? 1 : 0);
	array->clear           = (clear ? 1 : 0);
	array->elt_size        = elt_size;

	if(array->zero_terminated || reserved_size != 0)
	{
		maybe_expand(array, reserved_size);
		array_zero_terminate(array);
	}

	return (P11cArray*)array;
}

void*
p11c_array_free(P11cArray* array, int free_segment)
{
	void* segment;

	if(array == NULL)
		return NULL;

	if(free_segment)
	{
		if(array->data)
			free(array->data);
		segment = NULL;
	}
	else
		segment = array->data;

	free(array);
	return segment;
}

int
p11c_array_append_vals(P11cArray* parray, const void* data, size_t len)
{
	RealArray* array = (RealArray*)parray;
	if(!maybe_expand(array, len))
		return 0;

	memcpy(array_elt_pos(array, array->pub.len), data, 
	       array_elt_len(array, len));

	array->pub.len += len;
	array_zero_terminate(array);

	return 1;
}

void
p11c_array_remove_index(P11cArray* parray, unsigned int index)
{
	RealArray* array = (RealArray*)parray;

	if(index >= array->pub.len)
		return;

	if(index != array->pub.len - 1)
		memmove(array_elt_pos (array, index),
		        array_elt_pos (array, index + 1),
		        array_elt_len (array, array->pub.len - index - 1));
  
	array->pub.len -= 1;

	array_elt_zero (array, array->pub.len, 1);
}

void
p11c_array_remove_range(P11cArray* parray, unsigned int index, size_t length)
{
	RealArray *array = (RealArray*)parray;

	if(index >= array->pub.len)
		return;
	if(index + length > array->pub.len)
		length = array->pub.len - index;
	if(length == 0)
		return;

	if(index + length != array->pub.len)
		memmove(array_elt_pos (array, index), 
		        array_elt_pos (array, index + length), 
		        (array->pub.len - (index + length)) * array->elt_size);

	array->pub.len -= length;
	array_elt_zero(array, array->pub.len, length);
}


/*
 * Originally from apache 2.0
 * Extensive modifications by <nielsen@memberwebs.com>
 */

/* Copyright 2000-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/*
 * The internal form of a hash table.
 *
 * The table is an array indexed by the hash of the key; collisions
 * are resolved by hanging a linked list of hash entries off each
 * element of the array. Although this is a really simple design it
 * isn't too bad given that pools have a low allocation overhead.
 */

typedef struct _HashEntry 
{
	struct _HashEntry* next;
	unsigned int hash;
	const void* key;
	void* val;
}
HashEntry;

/*
 * The size of the array is always a power of two. We use the maximum
 * index rather than the size so that we can use bitwise-AND for
 * modular arithmetic.
 * The count of hash entries may be greater depending on the chosen
 * collision rate.
 */
struct _P11cHash 
{
	HashEntry** array;
	P11cHashFunc hash_func;
	P11cHashEqual equal_func;
	size_t count;
	size_t max;
};


#define INITIAL_MAX 15 /* tunable == 2^n - 1 */

static int 
equal_default(const void* a, const void* b)
{
	return a == b;
}

/*
 * Hash creation functions.
 */

static HashEntry** 
alloc_array(P11cHash* ht, size_t max)
{
	return calloc(1, sizeof(*(ht->array)) * (max + 1));
}

P11cHash* 
p11c_hash_new(P11cHashFunc hash_func, P11cHashEqual equal_func)
{
	P11cHash* ht = malloc(sizeof(P11cHash));
	if(ht)
	{
		ht->hash_func = hash_func ? hash_func : p11c_hash_pointer;
		ht->equal_func = equal_func ? equal_func : equal_default;
		ht->count = 0;
		ht->max = INITIAL_MAX;
		ht->array = alloc_array(ht, ht->max);
		if(!ht->array)
		{
			free(ht);
			ht = NULL;
		}
	}
	return ht;
}

void 
p11c_hash_free(P11cHash* ht, P11cHashDestroy destroy_func)
{
	HashEntry* he;
	HashEntry* next;
	size_t i;

	for(i = 0; i <= ht->max; ++i)
	{
		for(he = ht->array[i]; he; )
		{
			next = he->next;
			if(destroy_func)
				(destroy_func)((void*)he->val);
			free(he);
			he = next;
		}
	}
		
	if(ht->array)
		free(ht->array);	
	free(ht);
}

/*
 * Expanding a hash table
 */
static int 
expand_array(P11cHash* ht)
{
	HashEntry** new_array;
	size_t new_max;
	HashEntry* he;
	HashEntry* next;
	size_t i;

	new_max = ht->max * 2 + 1;
	new_array = alloc_array(ht, new_max);
	
	if(!new_array)
		return 0;
		
	for(i = 0; i <= ht->max; ++i)
	{
		for(he = ht->array[i], next = he ? he->next : NULL; 
		    he != NULL; he = next, next = next ? next->next : NULL)
		{
			unsigned int j = he->hash & new_max;
			he->next = new_array[j];
			new_array[j] = he;
		}
	}

	if(ht->array)
		free(ht->array);
	
	ht->array = new_array;
	ht->max = new_max;
	return 1;
}

/*
 * This is where we keep the details of the hash function and control
 * the maximum collision rate.
 *
 * If val is non-NULL it creates and initializes a new hash entry if
 * there isn't already one there; it returns an updatable pointer so
 * that hash entries can be removed.
 */

static HashEntry** 
find_entry(P11cHash* ht, const void* key, void* val)
{
	HashEntry** hep;
	HashEntry* he;
	unsigned int hash;

	hash = (ht->hash_func)(key);

	/* scan linked list */
	for(hep = &ht->array[hash & ht->max], he = *hep;
	    he; hep = &he->next, he = *hep) 
	{
		if(he->hash == hash && (ht->equal_func)(he->key, key))
			break;
	}
	
	if(he || !val)
		return hep;

	/* add a new entry for non-NULL val */
	he = malloc(sizeof(*he));
	if(he)
	{
		/* Key points to external data */
		he->key = key;
		he->next = NULL;
		he->hash = hash;
		he->val	= val;
	 
		*hep = he;		
		ht->count++;
	}
	
	return hep;
}

void* 
p11c_hash_get(P11cHash* ht, const void *key)
{
	HashEntry** he = find_entry(ht, key, NULL);
	if(he && *he)
		return (void*)((*he)->val);
	else
		return NULL;
}

int 
p11c_hash_set(P11cHash* ht, const void* key, void* val)
{
	HashEntry** hep = find_entry(ht, key, val);	
	if(hep && *hep) 
	{
		/* replace entry */
		(*hep)->key = key;
		(*hep)->val = val;
			
		/* check that the collision rate isn't too high */
		if(ht->count > ht->max) 
		{
			if(!expand_array(ht))
				return 0;
		}

		return 1;
	}
	
	return 0;
}

void* 
p11c_hash_rem(P11cHash* ht, const void* key)
{
	HashEntry** hep = find_entry(ht, key, NULL);
	void* val = NULL;

	if(hep && *hep)
	{
		HashEntry* old = *hep;
		*hep = (*hep)->next;
		--ht->count;
		val = (void*)old->val;
		free(old);
	}
	
	return val;
}
		
size_t 
p11c_hash_count(P11cHash* ht)
{
	return ht->count;
}

unsigned int
p11c_hash_pointer(const void* ptr)
{
	return (unsigned int)ptr;
}

unsigned int 
p11c_hash_data(const void* data, size_t n_data)
{
	unsigned int hash = 0;
	const unsigned char* end;
	const unsigned char* p;

	/*
	 * This is the popular `times 33' hash algorithm which is used by
	 * perl and also appears in Berkeley DB. This is one of the best
	 * known hash functions for strings because it is both computed
	 * very fast and distributes very well.
	 *
	 * The originator may be Dan Bernstein but the code in Berkeley DB
	 * cites Chris Torek as the source. The best citation I have found
	 * is "Chris Torek, Hash function for text in C, Usenet message
	 * <27038@mimsy.umd.edu> in comp.lang.c , October, 1990." in Rich
	 * Salz's USENIX 1992 paper about INN which can be found at
	 * <http://citeseer.nj.nec.com/salz92internetnews.html>.
	 *
	 * The magic of number 33, i.e. why it works better than many other
	 * constants, prime or not, has never been adequately explained by
	 * anyone. So I try an explanation: if one experimentally tests all
	 * multipliers between 1 and 256 (as I did while writing a low-level
	 * data structure library some time ago) one detects that even
	 * numbers are not useable at all. The remaining 128 odd numbers
	 * (except for the number 1) work more or less all equally well.
	 * They all distribute in an acceptable way and this way fill a hash
	 * table with an average percent of approx. 86%.
	 *
	 * If one compares the chi^2 values of the variants (see
	 * Bob Jenkins ``Hashing Frequently Asked Questions'' at
	 * http://burtleburtle.net/bob/hash/hashfaq.html for a description
	 * of chi^2), the number 33 not even has the best value. But the
	 * number 33 and a few other equally good numbers like 17, 31, 63,
	 * 127 and 129 have nevertheless a great advantage to the remaining
	 * numbers in the large set of possible multipliers: their multiply
	 * operation can be replaced by a faster operation based on just one
	 * shift plus either a single addition or subtraction operation. And
	 * because a hash function has to both distribute good _and_ has to
	 * be very fast to compute, those few numbers should be preferred.
	 *
	 *                        -- Ralf S. Engelschall <rse@engelschall.com>
	 */

	for(p = data, end = p + n_data; p != end; ++p)
		hash = hash * 33 + *p;

	return hash;
}

unsigned int 
p11c_hash_integer(int integer)
{
	return integer;
}

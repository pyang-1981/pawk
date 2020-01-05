/*
 * stack.c -- Implementation for stack functions for use by extensions.
 */

/* 
 * Copyright (C) 2012, 2013 the Free Software Foundation, Inc.
 * 
 * This file is part of GAWK, the GNU implementation of the
 * AWK Programming Language.
 * 
 * GAWK is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * GAWK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

#include <stdlib.h>

#include "stack.h"

#define INITIAL_STACK	20

//static size_t size;
//static void **stack;
//static int index = -1;

/* stack_empty --- return true if stack is empty */

int
simple_stack_empty(const struct simple_stack *s)
{
	return s->index < 0;
}

/* stack_top --- return top object on the stack */

void *
simple_stack_top(const struct simple_stack *s)
{
	if (simple_stack_empty(s) || s->elems == NULL)
		return NULL;

	return s->elems[s->index];
}

/* stack_pop --- pop top object and return it */

void *
simple_stack_pop(struct simple_stack *s)
{
	if (simple_stack_empty(s) || s->elems == NULL)
		return NULL;

	return s->elems[s->index--];
}

/* stack_push --- push an object onto the stack */

int simple_stack_push(void *object, struct simple_stack *s)
{
	void **new_elems;
	size_t new_size = 2 * s->size;

	if (s->elems == NULL) {
		s->elems = (void **) malloc(INITIAL_STACK * sizeof(void *));
		if (s->elems == NULL)
			return 0;
		s->size = INITIAL_STACK;
	} else if (s->index + 1 >= s->size) {
		if (new_size < s->size)
			return 0;
		new_elems = realloc(s->elems, new_size * sizeof(void *));
		if (new_elems == NULL)
			return 0;
		s->size = new_size;
		s->elems = new_elems;
	}

	s->elems[++s->index] = object;
	return 1;
}

/* Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Axel Neumann
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

/*
 * avl code based on:
 * http://eternallyconfuzzled.com/tuts/datastructures/jsw_tut_avl.aspx
 * where Julienne Walker said ( 28. 2. 2010 12:55):
 * ...Once again, all of the code in this tutorial is in the public domain.
 * You can do whatever you want with it, but I assume no responsibility
 * for any damages from improper use. ;-)
 */

#ifndef _AVL_H
#define _AVL_H

#include <stdint.h>


struct avl_node {
        void *key;
        int balance;
        struct avl_node * link[2];
};

struct avl_tree {
	uint16_t key_size;
        struct avl_node *root;
};


#define AVL_INIT_TREE(tree, size) do { 	tree.root = NULL; tree.key_size = (size); } while (0)
#define AVL_TREE(tree, size) struct avl_tree (tree) = { (size), NULL }


#define AVL_MAX_HEIGHT 128

#define avl_height(p) ((p) == NULL ? -1 : (p)->balance)
#define avl_max(a,b) ((a) > (b) ? (a) : (b))

void *avl_find( struct avl_tree *tree, void *key );
void *avl_next( struct avl_tree *tree, void *key );
void avl_insert(struct avl_tree *tree, void *key);
void avl_remove(struct avl_tree *tree, void *key);



#endif
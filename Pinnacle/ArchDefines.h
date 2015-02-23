/*
 * File: ArchDefines.h
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 20, 2011, 4:36 PM
 */

#ifndef ARCHDEFINES_H
#define ARCHDEFINES_H

// We divide a BITS address space in pages of PAGE_SIZE size
#define PAGE_SHIFT  	(22)                // 4 megabytes
#define PAGE_SIZE   	(1 << PAGE_SHIFT)   // 4 megabytes
#define BITMAP_SIZE 	(PAGE_SIZE)

#define BITS        	(32)
#define NPAGES      	((1 << BITS) / PAGE_SIZE)

#define PAGE_ID(x)     	((x) >> PAGE_SHIFT)
#define PAGE_OFFSET(x) 	(((1 << PAGE_SHIFT) - 1) & (x))

#define PAGE_ALIG(x)    (((x >> PAGE_SHIFT) << PAGE_SHIFT))
#define PAGE_NEXT(x)    (((x >> PAGE_SHIFT) << PAGE_SHIFT) + PAGE_SIZE)

#endif // ARCHDEFINES_H

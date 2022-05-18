#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "SKREAM",
    /* First member's full name */
    "spektre",
    /* First member's email address */
    "spektre@bi0s.pwn",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""};

// Macros
#define ALIGNMENT 8
#define align(size) (((size) + (ALIGNMENT - 1)) & ~0x7)
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define WSIZE 4
#define DSIZE 8
#define MINBLOCKSIZE 16
#define get_4head(p) (*(size_t *)(p))
#define get_tail(p) (*(int *)(p))
#define sizet(p) size_t p
#define allocated 0xAAAAAAAA // value of the allocated block
#define free 0xBBBBBBBB      // value of the freed block
// Global variables
static void *list = 0xBBBBBBBB;

// coaleases with the next block
void *coalesce(void *blk1, void *blk2)
{

    // check if the blocks are adjacent
    if (blk1 + get_4head(blk1) + DSIZE != blk2)
    {
        return;
    }
    // get the size of the block we want to coalesce
    size_t size = get_4head(blk1) + get_4head(blk1) + DSIZE;
    // set the size of the block we want to coalesce
    get_4head(blk1) = size;
    // set the next block pointer to the next block
    get_tail(blk1 + WSIZE) = get_tail(blk2 + WSIZE);
    // set the header bytes of blk2 to 0
    memset(blk2, 0, DSIZE);
    return blk1;
}
/*
split the block into two blocks. The first block will be of size_t size.
*/
void *split(void *p, size_t size_d)
{ // if the size difference is zero return the original block
    if (size_d == 0)
    {
        return p;
    }
    else
    {
        // get the size of block we want to split to
        size_t size = get_4head(p) - size_d;

        // new block pointer to split block
        void *p_new = p + size + DSIZE;
        // set size in header of new block
        get_4head(p) = size;
        get_tail(p + WSIZE) = p_new;
        get_4head(p_new) = size_d - DSIZE;
        return p;
    }
}

void link_block(void *blk)
{
    if (list == free || list > blk)
    {
        get_tail(blk + WSIZE) = list;
        list = blk;
        coalesce(blk, list);
        return;
    }
    else
    {
        void *a = list;
        if (a < blk)
        {
            get_tail(blk + WSIZE) = get_tail(a + WSIZE);
            get_tail(a + WSIZE) = blk;
            coalesce(a, blk);
            return;
        }
        a = get_tail(a + WSIZE);
    }
}

void *find_fit(size_t size)
{
    // check if the block is the first block
    if (list == free)
    {
        return NULL;
    }
    void *ptr2 = list;
    void *prev = 0;
    if (get_4head(ptr2) >= size)
    {
        size_t size_d = get_4head(ptr2) - size;
        void *next = get_tail(ptr2 + WSIZE);
        void *a = split(ptr2, size_d);
        void *b = get_tail(a + WSIZE);
        if (b != next)
        {
            get_tail(b + WSIZE) = next;
        }
        if (prev == 0)
        {
            list = b;
            return a;
        }
        get_tail(prev + WSIZE) = b;
        return a;
    }
    prev = ptr2;
    ptr2 = get_tail(ptr2 + WSIZE);
    return NULL;
}

// initialize the heap with a single free block of size MINBLOCKSIZE
int mm_init(void)
{
    void *ptr = mem_sbrk(MINBLOCKSIZE);
    list = free;
    if (ptr == NULL)
    {
        return -1;
    }
    mm_free(ptr);
    return 0;
}

/*
Alligns the size and checks if it is less than min block size. then search for a block that fits the size.
if not found, then call sbrk to get more memory.
and return the pointer
*/

void *mm_malloc(size_t size)
{
    int asize;
    if (size < MINBLOCKSIZE)
    {
        asize = MINBLOCKSIZE;
    }
    asize = align(size);
    // check if the size is 0
    if (size == 0)
    {
        return;
    }
    // search for the block in the list
    void *a = find_fit(asize);
    // check if the block is found
    if (a != NULL)
    {
        get_tail(a + WSIZE) = allocated;
        return (void *)(a + DSIZE);
    }
    // ptr for new allocation
    void *ptr = mem_sbrk(asize + DSIZE);
    // check if the allocation is successful
    if (ptr == -1)
    {
        return NULL;
    }
    else
    {
        // set the size of the block
        get_4head(ptr) = size;
        // set the allocated block
        get_tail(ptr + WSIZE) = allocated;

        return (void *)(ptr + DSIZE);
    }
}
void mm_free(void *ptr)
{
    // check if the pointer is allocated
    if (get_tail(ptr - WSIZE) != allocated)
    {
        return;
    }
    // set the header_t bytes to free
    else
    {
        // get size of the block
        size_t size = get_4head(ptr - DSIZE);
        // Nulls the block
        memset(ptr, 0, size);
        // link the block to the list
        link_block(ptr - DSIZE);
    }
}

void *mm_realloc(void *ptr, size_t size)
{
    // get the size of the block
    size_t size_ptr = get_4head(ptr - DSIZE);
    // check if the size required is less than the size of the block
    if (size < size_ptr)
    {
        size_ptr = size;
    }
    // allocate the new block
    void *ptr2 = mm_malloc(size);
    if (ptr2 == NULL)
    {
        // returns null of allocation fails
        return NULL;
    }
    // copy the data from the old block to the new block
    memcpy(ptr2, ptr, size_ptr);
    // free the old block
    mm_free(ptr);
    return ptr2;
}
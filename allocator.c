/*
 * File: allocator.c
 * Author: YOUR NAME HERE
 * ----------------------
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include "allocator.h"
#include "segment.h"

#define ALIGNMENT 8
#define MINIMUM 16
#define BUCKETS 64
#define INITIAL_HEAP_SIZE 1
#define OVERALLOCATE 2

typedef struct Header Header;

typedef struct Header{
    size_t ss;   // header contains just one 8-byte field
    Header *one; //prev or left
    Header *two; // next or right
} Header;

typedef struct Footer{
    size_t fss;
} Footer;

Header *free_buckets[BUCKETS];

void *start;
void *lastAddr;

// Very efficient bitwise round of sz up to nearest multiple of mult
// does this by adding mult-1 to sz, then masking off the
// the bottom bits to compute least multiple of mult that is
// greater/equal than sz, this value is returned
// NOTE: mult has to be power of 2 for the bitwise trick to work!
static inline size_t roundup(size_t sz, size_t mult)
{
    return (sz + mult-1) & ~(mult-1);
}

// Given a pointer to start of payload, simply back up
// to access its block header
static inline Header *get_pre_header(void *v)
{
    return (Header *)((char *)v - sizeof(size_t));
}

static inline size_t get_size(Header *h){
    return h->ss >> 1;
}

static inline size_t get_status(Header *h){
    return h->ss&0x1;
}

static inline Header *get_post_header(void *v){
    Header *h = get_pre_header(v);
    return (Header *)((char *)h + sizeof(size_t) + get_size(h) + sizeof(Footer));
}

static inline Header* get_next_header(Header* h) {
    return (Header *)((char*) h + sizeof(size_t) + get_size(h) + sizeof(Footer));
}


static inline Header *get_one(Header *h){
    return h->one;
}

static inline void set_one(Header *h,Header *l){
    h->one = l;
}

static inline Header *get_two(Header *h){
    return h->two;
}

static inline void set_two(Header *h,Header *l){
    h->two = l;
}

static inline void set_header(Header *h,size_t size,size_t status) {
    h->ss = (size << 1) + status;
}

static inline void set_footer(Footer *f,size_t size,size_t status) {
    f->fss = (size << 1) + status;
}

static inline Footer *get_footer(Header *h){
    return (Footer *) ((char *)h + sizeof(size_t) + get_size(h));
}

static inline size_t get_footer_size(Footer *f){
    return f->fss >> 1;
}

static inline size_t get_footer_status(Footer *f){
    return f->fss & 0x1;
}

static inline Footer* get_prev_footer(Header *h) {
    return (Footer *) ((char*)h - sizeof(Footer));
}

static inline Header* get_header_from_footer(Footer *f) {
    return (Header *) ((char*)f - get_footer_size(f) - sizeof(size_t));
}

void set_ss(Header *h,size_t size, size_t status){
    set_header(h,size,status);
    Footer *f = get_footer(h);
    set_footer(f,size,status);
}

// Given a pointer to block header, advance past
// header to access start of payload
static inline void *get_block(Header *header){

    return (char *)header + sizeof(size_t);
}

Header *create_free_block(void *v,size_t sz){
    Header *h = (Header *)v;
    set_ss(h,sz,0);
    h->one = NULL;
    h->two = NULL;
    return h;
}


/* The responsibility of the myinit function is to configure a new
 * empty heap. Typically this function will initialize the
 * segment (you decide the initial number pages to set aside, can be
 * zero if you intend to defer until first request) and set up the
 * global variables for the empty, ready-to-go state. The myinit
 * function is called once at program start, before any allocation 
 * requests are made. It may also be called later to wipe out the current
 * heap contents and start over fresh. This "reset" option is specifically
 * needed by the test harness to run a sequence of scripts, one after another,
 * without restarting program from scratch.
 */

// 16 -248 have own buckets. Bigger blocks are distributed logarithmically . Huge blocks are
// assigned to the last bucket.
size_t log_two(size_t num){
    int result = __builtin_clzll(num);
    result = 63 - result;
    return (size_t)result;
}

size_t hash_size(size_t size){
    if(size <= 248){
        return size/ALIGNMENT;
    }
    size_t log_index;
    log_index = log_two(size);
    log_index += 24;
    if(log_index <= 63)
        return log_index;
    return BUCKETS -1;
    // do log stuff log3(sz)
}

void add_node(Header *node, Header *h){
    if(get_size(h) < get_size(node)){
        if(node->one == NULL) {
            node->one = h;
            return;
        }
        add_node(node->one,h);
    } else {
        if(node->two == NULL) {
            node->two = h;
            return;
        }
        add_node(node->two,h);
    }
}

//assume h has no pointers
void add_to_buckets(Header *h){
   size_t index = hash_size(get_size(h));
   if(index >= 32){// placeholder change to 32 later
        //binary tree addition
        if(free_buckets[index] == NULL) {
            free_buckets[index] = h;
            return;
        }
        add_node(free_buckets[index],h);
   } else {
        if(free_buckets[index] != NULL){
            free_buckets[index]->one = h;//make the top of the list's prev pointer point to h
            h->two = free_buckets[index];// make h's next ptr set to the top of the list
        }
        free_buckets[index] = h;//make the h the top of the list
   }
}

bool myinit()
{
    void *v = init_heap_segment(INITIAL_HEAP_SIZE); // reset heap segment to empty, no pages allocated
    start = v;
    lastAddr = (char *)start + PAGE_SIZE*INITIAL_HEAP_SIZE;
    if(v == NULL)
        return false;
    size_t sz = INITIAL_HEAP_SIZE * PAGE_SIZE - sizeof(Footer) - sizeof(size_t);//need to change if we use tight
    Header *h = create_free_block(v,sz);
    for(int i = 0; i < BUCKETS; i++){
        free_buckets[i] = NULL;
    }
    add_to_buckets(h);
    return true;
}


Header *biggest_node(Header *node){
    if(node->two == NULL)
        return node;
    return biggest_node(node->two);
}

Header *find_prev(Header *node,Header *h, int *direction){
    if(node == NULL)
        return NULL;
    if(node->one == h){
        *direction = 1;
        return node;
    }
    if(node->two == h){
        *direction = 2;
        return node;
    }
    if(get_size(h) < get_size(node)){
        return find_prev(node->one,h,direction);
    }
    return find_prev(node->two,h,direction);
}

int numChildren(Header* h) {
    int numChil = 0;
    if(h->one != NULL)
        numChil++;
    if(h->two != NULL)
        numChil++;
    return numChil;
}

void remove_header_BST(Header* top, Header* target, int index) {
    Header* prev = NULL;
    int leftOrRight = 0; //left = 1, right = 2
    if (top != target) {
        prev = find_prev(top, target, &leftOrRight);
    }
    if (numChildren(target) == 0) {
        if (leftOrRight == 0) {
            free_buckets[index] = NULL;
        } 
        if (leftOrRight == 1) {
            prev->one = NULL;
        } 
        if (leftOrRight == 2) {
            prev->two = NULL;
        }
        return;
    }
    if (numChildren(target) == 1) {
        if (leftOrRight == 0) { //prev is NULL
            if (target->one != NULL) {
                free_buckets[index] = target->one; 
            } else {
                free_buckets[index] = target->two;
            }
        } 
        if (leftOrRight == 1) { //prev left child is target
            if (target->one != NULL) {
                prev->one = target->one;
            } else {
                prev->one = target->two;
            }
        } 
        if (leftOrRight == 2) { //prev right child is target
            if (target->one != NULL) {
                prev->two = target->one; 
            } else {
                prev->two = target->two;
            }
        }
        return;
    }

    if (numChildren(target) == 2) {
        Header* biggestNode = biggest_node(target->one);
        biggestNode->one = target->one;
        biggestNode->two = target->two;
        remove_header_BST(top, biggestNode, index);
        if (leftOrRight == 0) {
            free_buckets[index] = biggestNode;
            return;
        }
        if (leftOrRight == 1) {
            prev->one = biggestNode;
            return;
        } 
        if (leftOrRight == 2) {
            prev->two = biggestNode;
            return; 
        }
    }
}


//at this point it is still free - there should be pointers
void remove_free_header(Header *h){
    size_t size = get_size(h);
    if(size < 256){
        if(h->one == NULL){// at front of linked list
            size_t index = hash_size(size);
            free_buckets[index] = h->two;
            return;
        }
        (h->one)->two = h->two;//set prev's next to h's next;
        return;
    } else {
        size_t index = hash_size(size);
        remove_header_BST(free_buckets[index],h,index);
    }
}

void combine(Header* one, Header *two) {
    size_t totalSize = get_size(one) + sizeof(Footer) + sizeof(size_t) + get_size(two);
    remove_free_header(one);
    create_free_block(one, totalSize);
    remove_free_header(two);
    one->one = NULL;
    one->two = NULL;
    add_to_buckets(one);
}

void coalesce(Header* freed) {
    Header* next = get_next_header(freed);
    if (get_status(next) == 0) {
        combine(freed, next);
    }
    Footer* prevFooter = get_prev_footer(freed);
    if (get_footer_status(prevFooter) == 0) {
        Header* prevHeader = get_header_from_footer(prevFooter);
        combine(prevHeader, freed);
    }
}

Header* getFixedFree(size_t sz) {
    size_t index = hash_size(sz);
    for(int i = index; i < BUCKETS/2; i++){
        Header* free = free_buckets[i];
        if (free != NULL) {
            return free;
        }
    }
    return NULL;   
}

Header* traverse(Header* node, size_t sz) {
    if (node == NULL) {
        return NULL;
    }
    if (get_size(node) >= sz) {
        return node;
    }
    if (get_size(node) < sz) {
        return traverse(node->two,sz);
    }
    return NULL;
}

Header* getVariableFree(size_t sz) {
    size_t index;
    if (sz < 256) {
        index = 32;
    } else {
        index = hash_size(sz);
    }
    for(int i = index; i < BUCKETS; i++){
        Header* top = free_buckets[i];
        Header* free = traverse(top, sz);
        if (free != NULL) {
            return free;
        }
    }
    return NULL;   

}

void extend_heap(size_t sz){
    size_t pages = 1;
    size_t add_pages = 0;
    Header *h;
    
    size_t shortage = 0;
    if(sz >= (PAGE_SIZE - (sizeof(size_t) + sizeof(Footer))))
        shortage = sz - (PAGE_SIZE - (sizeof(size_t) + sizeof(Footer)));

    if(shortage > 0){
        size_t total_needed = roundup(shortage,PAGE_SIZE);
        add_pages = total_needed / PAGE_SIZE;
        pages += add_pages;
    }

    h = (Header *)extend_heap_segment(pages);
    size_t total = PAGE_SIZE * pages - (sizeof(size_t) + sizeof(Footer));
    lastAddr = (char*)h + PAGE_SIZE*pages;
    create_free_block(h,total);
    add_to_buckets(h);
}

Header* getFree(size_t sz) {
    Header* free;
    if (sz < 256) {
        free = getFixedFree(sz);
        if (free != NULL) {
            return free;
        }
    }
    free = getVariableFree(sz);
    if (free == NULL) {
        extend_heap(sz);
        free = getVariableFree(sz);
        if(free == NULL)// the case that no more space could be allocated
            return NULL;
    }
    return free;
}
// malloc a block by rounding up size to number of pages, extending heap
// segment and using most recently added page(s) for this block. This
// means each block gets its own page -- how generous! :-)
void *mymalloc(size_t requestedsz)
{
    if (((int) requestedsz > INT_MAX) || (requestedsz == 0))
        return NULL;
    size_t sz = roundup(requestedsz, ALIGNMENT);
    if (sz < MINIMUM) {
        sz = MINIMUM;
    }
    Header* free = getFree(sz);
    if (free == NULL) {
        return NULL;
    }
    //could skip removing it if (sz + 32 > originalsz)
    remove_free_header(free);
    size_t originalsz = get_size(free);
    set_ss(free,sz,1);
    Header* post = get_next_header(free);
    
    if(sz + sizeof(size_t) + sizeof(Footer) + MINIMUM > originalsz)
        sz = originalsz;

    if(originalsz == sz){

    } else {
        if ((size_t)post + sizeof(size_t) + MINIMUM + sizeof(Footer) < (size_t)lastAddr) {
            size_t postsz = originalsz - sizeof(Footer) - sizeof(size_t) - sz;
            create_free_block(post,postsz);
            add_to_buckets(post);
        }
    }
    return get_block(free);
}

// free does nothing.  fast!... but lame :(
void myfree(void *ptr)
{
    if(ptr == NULL)
        return;
    Header *h;
    h = get_pre_header(ptr);
    //coalesce (conditionally ?)
    size_t sz = get_size(h);
    create_free_block(h,sz);
    add_to_buckets(h);
}

// realloc built on malloc/memcpy/free is easy to write.
// This code will work ok on ordinary cases, but needs attention
// to robustness. Realloc efficiency can be improved by
// implementing a standalone realloc as opposed to
// delegating to malloc/free.
void *myrealloc(void *oldptr, size_t newsz)
{
    size_t oldsz = get_size(get_pre_header(oldptr));

    if(roundup(newsz,ALIGNMENT) <= oldsz)
        return oldptr;
    void *newptr = mymalloc(newsz * OVERALLOCATE);
    memcpy(newptr, oldptr,oldsz < newsz ? oldsz: newsz);
    myfree(oldptr);
    return newptr;
}


// validate_heap is your debugging routine to detect/report
// on problems/inconsistency within your heap data structures
bool validate_heap()
{   /*
    Header* currHeader = start;
    while((size_t) currHeader < (size_t) lastAddr) {
        size_t sz = get_size(currHeader);
        Footer* currFooter = (Footer *)((char*)currHeader + sizeof(size_t) + sz);
        size_t szf = get_footer_size(currFooter);
        if (sz != szf) {
            return false;
        }
        currHeader = (Header*)((char*)currFooter+sizeof(Footer));
        printf("looks good guys!\n");
    }*/
    return true;
}

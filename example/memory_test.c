#include<stdio.h>
#include<stdlib.h>
#define ZEND_MM_ALIGNMENT 8
#define ZEND_MM_ALIGNMENT_LOG2 3
#define MEM_BLOCK_VALID  0x7312F8DC
#define	MEM_BLOCK_FREED  0x99954317
#define	MEM_BLOCK_CACHED 0xFB8277DC
#define	MEM_BLOCK_GUARD  0x2A8FCC84
#define	MEM_BLOCK_LEAK   0x6C5E8F2D
#define ZEND_MM_ALIGNMENT_MASK ~(ZEND_MM_ALIGNMENT-1)
//分配内存大小
#define ZEND_MM_ALIGNED_SIZE(size)	(((size) + ZEND_MM_ALIGNMENT - 1) & ZEND_MM_ALIGNMENT_MASK)

#define EXPECTED(condition)   (condition)
#define UNEXPECTED(condition) (condition)


typedef struct _zend_mm_segment {
	size_t	size;
	struct _zend_mm_segment *next_segment;
} zend_mm_segment;

typedef struct _zend_mm_storage zend_mm_storage;

typedef struct _zend_mm_mem_handlers {
	const char *name;
	zend_mm_storage* (*init)(void *params);
	void (*dtor)(zend_mm_storage *storage);
	void (*compact)(zend_mm_storage *storage);
	zend_mm_segment* (*_alloc)(zend_mm_storage *storage, size_t size);
	zend_mm_segment* (*_realloc)(zend_mm_storage *storage, zend_mm_segment *ptr, size_t size);
	void (*_free)(zend_mm_storage *storage, zend_mm_segment *ptr);
} zend_mm_mem_handlers;


struct _zend_mm_storage {
	const zend_mm_mem_handlers *handlers;
	void *data;
};


typedef struct _zend_mm_block_info {
	size_t _size;
	size_t _prev;
} zend_mm_block_info;

typedef struct _zend_mm_block {
	zend_mm_block_info info;
} zend_mm_block;

typedef struct _zend_mm_small_free_block {
	zend_mm_block_info info;
	struct _zend_mm_free_block *prev_free_block;
	struct _zend_mm_free_block *next_free_block;
} zend_mm_small_free_block;

typedef struct _zend_mm_free_block {
	zend_mm_block_info info;
	struct _zend_mm_free_block *prev_free_block;
	struct _zend_mm_free_block *next_free_block;

	struct _zend_mm_free_block **parent;
	struct _zend_mm_free_block *child[2];
} zend_mm_free_block;

#define ZEND_MM_NUM_BUCKETS (sizeof(size_t) << 3);

struct _zend_mm_heap {
	int                 use_zend_alloc;
	void               *(*_malloc)(size_t);
	void                (*_free)(void*);
	void               *(*_realloc)(void*, size_t);
	size_t              free_bitmap;
	size_t              large_free_bitmap;
	size_t              block_size;
	size_t              compact_size;
	zend_mm_segment    *segments_list;
	zend_mm_storage    *storage;
	size_t              real_size; //真实大小
	size_t              real_peak; //峰值
	size_t              limit;
	size_t              size;
	size_t              peak;
	size_t              reserve_size;
	void               *reserve;
	int                 overflow;
	int                 internal;
	zend_mm_free_block *free_buckets[32*2];
	zend_mm_free_block *large_free_buckets[32];
	zend_mm_free_block *rest_buckets[2];
};

typedef struct _zend_mm_heap zend_mm_heap;

//(zend_mm_free_block*) ((char*)&heap->free_buckets[index * 2] 得到的是索引为index*2的元素的地址
//sizeof(zend_mm_free_block*) * 2 - sizeof(zend_mm_small_free_block)) = -sizeof(zend_mm_block_info)
#define ZEND_MM_SMALL_FREE_BUCKET(heap, index) \
	(zend_mm_free_block*) ((char*)&heap->free_buckets[index * 2] + \
		sizeof(zend_mm_free_block*) * 2 - \
		sizeof(zend_mm_small_free_block))

#define ZEND_MM_REST_BUCKET(heap) \
	(zend_mm_free_block*)((char*)&heap->rest_buckets[0] + \
		sizeof(zend_mm_free_block*) * 2 - \
		sizeof(zend_mm_small_free_block))

# define END_MAGIC_SIZE 0

/* Default memory segment size */
#define ZEND_MM_SEG_SIZE   (256 * 1024)

/* Reserved space for error reporting in case of memory overflow */
//8KB
#define ZEND_MM_RESERVE_SIZE            (8*1024)

#ifdef _WIN64
# define ZEND_MM_LONG_CONST(x)	(x##i64)
#else
# define ZEND_MM_LONG_CONST(x)	(x##L)
#endif

#define ZEND_MM_TYPE_MASK		ZEND_MM_LONG_CONST(0x3)

#define ZEND_MM_FREE_BLOCK		ZEND_MM_LONG_CONST(0x0)
#define ZEND_MM_USED_BLOCK		ZEND_MM_LONG_CONST(0x1)
#define ZEND_MM_GUARD_BLOCK		ZEND_MM_LONG_CONST(0x3)

# define ZEND_MM_CHECK_BLOCK_LINKAGE(block)
# define ZEND_MM_CHECK_TREE(block)
# define ZEND_MM_SET_COOKIE(block)
# define ZEND_MM_CHECK_COOKIE(block)

#define ZEND_MM_BLOCK(b, type, size)	do { \
											size_t _size = (size); \
											(b)->info._size = (type) | _size; \
											ZEND_MM_BLOCK_AT(b, _size)->info._prev = (type) | _size; \
											ZEND_MM_SET_COOKIE(b); \
										} while (0);

#define ZEND_MM_LAST_BLOCK(b)			do { \
		(b)->info._size = ZEND_MM_GUARD_BLOCK | ZEND_MM_ALIGNED_HEADER_SIZE; \
		ZEND_MM_SET_MAGIC(b, MEM_BLOCK_GUARD); \
 	} while (0);


# define ZEND_MM_VALID_PTR(ptr) EXPECTED(ptr != NULL)

# define ZEND_MM_SET_MAGIC(block, val)

# define ZEND_MM_CHECK_MAGIC(block, val)

#define ZEND_MM_SET_BLOCK_SIZE(block, _size)

# define ZEND_MM_SET_DEBUG_INFO(block, __size, set_valid, set_thread) ZEND_MM_SET_BLOCK_SIZE(block, __size)


#define ZEND_MM_BLOCK_SIZE(b)			((b)->info._size & ~ZEND_MM_TYPE_MASK)
#define ZEND_MM_IS_FREE_BLOCK(b)		(!((b)->info._size & ZEND_MM_USED_BLOCK))
#define ZEND_MM_IS_USED_BLOCK(b)		((b)->info._size & ZEND_MM_USED_BLOCK)
#define ZEND_MM_IS_GUARD_BLOCK(b)		(((b)->info._size & ZEND_MM_TYPE_MASK) == ZEND_MM_GUARD_BLOCK)

#define ZEND_MM_NEXT_BLOCK(b)			ZEND_MM_BLOCK_AT(b, ZEND_MM_BLOCK_SIZE(b))
#define ZEND_MM_PREV_BLOCK(b)			ZEND_MM_BLOCK_AT(b, -(ssize_t)((b)->info._prev & ~ZEND_MM_TYPE_MASK))

#define ZEND_MM_PREV_BLOCK_IS_FREE(b)	(!((b)->info._prev & ZEND_MM_USED_BLOCK))

#define ZEND_MM_MARK_FIRST_BLOCK(b)		((b)->info._prev = ZEND_MM_GUARD_BLOCK)
#define ZEND_MM_IS_FIRST_BLOCK(b)		((b)->info._prev == ZEND_MM_GUARD_BLOCK)

/* optimized access */
#define ZEND_MM_FREE_BLOCK_SIZE(b)		(b)->info._size

/* Aligned header size */
//ZEND_MM_ALIGNED_HEADER_SIZE = 16个字节
#define ZEND_MM_ALIGNED_HEADER_SIZE			ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_block))
//ZEND_MM_ALIGNED_FREE_HEADER_SIZE = 32个字节
#define ZEND_MM_ALIGNED_FREE_HEADER_SIZE	ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_small_free_block))
//END_MAGIC_SIZE在下面被定义 END_MAGIC_SIZE=0
//ZEND_MM_MIN_ALLOC_BLOCK_SIZE = 16
#define ZEND_MM_MIN_ALLOC_BLOCK_SIZE		ZEND_MM_ALIGNED_SIZE(ZEND_MM_ALIGNED_HEADER_SIZE + END_MAGIC_SIZE)
//ZEND_MM_ALIGNED_MIN_HEADER_SIZE = 32
#define ZEND_MM_ALIGNED_MIN_HEADER_SIZE		(ZEND_MM_MIN_ALLOC_BLOCK_SIZE>ZEND_MM_ALIGNED_FREE_HEADER_SIZE?ZEND_MM_MIN_ALLOC_BLOCK_SIZE:ZEND_MM_ALIGNED_FREE_HEADER_SIZE)
// 	ZEND_MM_ALIGNED_SEGMENT_SIZE = 16
#define ZEND_MM_ALIGNED_SEGMENT_SIZE		ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_segment))
// ZEND_MM_MIN_SIZE = 16
#define ZEND_MM_MIN_SIZE					((ZEND_MM_ALIGNED_MIN_HEADER_SIZE>(ZEND_MM_ALIGNED_HEADER_SIZE+END_MAGIC_SIZE))?(ZEND_MM_ALIGNED_MIN_HEADER_SIZE-(ZEND_MM_ALIGNED_HEADER_SIZE+END_MAGIC_SIZE)):0)

// ZEND_MM_MAX_SMALL_SIZE = 544
#define ZEND_MM_MAX_SMALL_SIZE				((32<<ZEND_MM_ALIGNMENT_LOG2)+ZEND_MM_ALIGNED_MIN_HEADER_SIZE)

#define ZEND_MM_TRUE_SIZE(size)				((size<ZEND_MM_MIN_SIZE)?(ZEND_MM_ALIGNED_MIN_HEADER_SIZE):(ZEND_MM_ALIGNED_SIZE(size+ZEND_MM_ALIGNED_HEADER_SIZE+END_MAGIC_SIZE)))

#define ZEND_MM_BUCKET_INDEX(true_size)		((true_size>>ZEND_MM_ALIGNMENT_LOG2)-(ZEND_MM_ALIGNED_MIN_HEADER_SIZE>>ZEND_MM_ALIGNMENT_LOG2))

#define ZEND_MM_SMALL_SIZE(true_size)		(true_size < ZEND_MM_MAX_SMALL_SIZE)

/* Memory calculations */
#define ZEND_MM_BLOCK_AT(blk, offset)	((zend_mm_block *) (((char *) (blk))+(offset)))
#define ZEND_MM_DATA_OF(p)				((void *) (((char *) (p))+ZEND_MM_ALIGNED_HEADER_SIZE))
#define ZEND_MM_HEADER_OF(blk)			ZEND_MM_BLOCK_AT(blk, -(int)ZEND_MM_ALIGNED_HEADER_SIZE)


static zend_mm_storage* zend_mm_mem_dummy_init(void *params)
{
	return malloc(sizeof(zend_mm_storage));
}

static void zend_mm_mem_dummy_dtor(zend_mm_storage *storage)
{
	free(storage);
}

static void zend_mm_mem_dummy_compact(zend_mm_storage *storage)
{
}
static zend_mm_segment* zend_mm_mem_malloc_alloc(zend_mm_storage *storage, size_t size)
{
	return (zend_mm_segment*)malloc(size);
}

static zend_mm_segment* zend_mm_mem_malloc_realloc(zend_mm_storage *storage, zend_mm_segment *ptr, size_t size)
{
	return (zend_mm_segment*)realloc(ptr, size);
}

static void zend_mm_mem_malloc_free(zend_mm_storage *storage, zend_mm_segment *ptr)
{
	free(ptr);
}

# define ZEND_MM_MEM_MALLOC_DSC {"malloc", zend_mm_mem_dummy_init, zend_mm_mem_dummy_dtor, zend_mm_mem_dummy_compact, zend_mm_mem_malloc_alloc, zend_mm_mem_malloc_realloc, zend_mm_mem_malloc_free}


static const zend_mm_mem_handlers mem_handlers[] = {
	ZEND_MM_MEM_MALLOC_DSC,
	{NULL, NULL, NULL, NULL, NULL, NULL}
};


# define ZEND_MM_STORAGE_DTOR()						heap->storage->handlers->dtor(heap->storage)
# define ZEND_MM_STORAGE_ALLOC(size)				heap->storage->handlers->_alloc(heap->storage, size)
# define ZEND_MM_STORAGE_REALLOC(ptr, size)			heap->storage->handlers->_realloc(heap->storage, ptr, size)
# define ZEND_MM_STORAGE_FREE(ptr)					heap->storage->handlers->_free(heap->storage, ptr)

//最高位1的序号
#define ZEND_MM_LARGE_BUCKET_INDEX(S) zend_mm_high_bit(S)

static inline unsigned int zend_mm_high_bit(size_t _size)
{
#if defined(__GNUC__) && defined(i386)
	unsigned int n;

	__asm__("bsrl %1,%0\n\t" : "=r" (n) : "rm"  (_size));
	return n;
#elif defined(__GNUC__) && defined(__x86_64__)
	unsigned long n;

        __asm__("bsrq %1,%0\n\t" : "=r" (n) : "rm"  (_size));
        return (unsigned int)n;
#elif defined(_MSC_VER) && defined(_M_IX86)
	__asm {
		bsr eax, _size
	}
#else
	unsigned int n = 0;
	while (_size != 0) {
		_size = _size >> 1;
		n++;
	}
	return n-1;
#endif
}

static inline unsigned int zend_mm_low_bit(size_t _size)
{
#if defined(__GNUC__) && defined(i386)
	unsigned int n;

	__asm__("bsfl %1,%0\n\t" : "=r" (n) : "rm"  (_size));
	return n;
#elif defined(__GNUC__) && defined(__x86_64__)
        unsigned long n;

        __asm__("bsfq %1,%0\n\t" : "=r" (n) : "rm"  (_size));
        return (unsigned int)n;
#elif defined(_MSC_VER) && defined(_M_IX86)
	__asm {
		bsf eax, _size
   }
#else
	static const int offset[16] = {4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0};
	unsigned int n;
	unsigned int index = 0;

	n = offset[_size & 15];
	while (n == 4) {
		_size >>= 4;
		index += n;
		n = offset[_size & 15];
	}

	return index + n;
#endif
}

static inline void zend_mm_init(zend_mm_heap *heap)
{
	zend_mm_free_block* p;
	int i;

	heap->free_bitmap = 0;
	heap->large_free_bitmap = 0;
	//此时，p指向第一个元素的prev_free_block属性的地址
	p = ZEND_MM_SMALL_FREE_BUCKET(heap, 0);
	/**
	//参考文档：http://www.laruence.com/2011/11/09/2277.html
	Q: 为什么free_buckets数组的长度是ZEND_MM_NUMBER_BUCKET个?
	A: 这是因为, PHP在这处使用了一个技巧, 用一个定长的数组来存储ZEND_MM_NUMBER_BUCKET个zend_mm_free_block, 
	    对于一个没有被使用的free_buckets的元素, 唯一有用的数据结构就是next_free_block和prev_free_block, 
	    所以, 为了节省内存, PHP并没有分配ZEND_MM_NUMBER_BUCKET * sizeof(zend_mm_free_block)大小的内存, 
	    而只是用了ZEND_MM_NUMBER_BUCKET * (sizeof(*next_free_block) + sizeof(*prev_free_block))大小的内存.
	 */
	for (i = 0; i < 32; i++) {
		p->next_free_block = p;
		p->prev_free_block = p;
		printf("i:%d,%d,%d\n",i,p->next_free_block,p->prev_free_block);
		p = (zend_mm_free_block*)((char*)p + sizeof(zend_mm_free_block*) * 2);
		heap->large_free_buckets[i] = NULL;
	}
	heap->rest_buckets[0] = heap->rest_buckets[1] = ZEND_MM_REST_BUCKET(heap);
}

zend_mm_heap *zend_mm_startup_ex(const zend_mm_mem_handlers *handlers, size_t block_size, size_t reserve_size, int internal, void *params)
{
	zend_mm_storage *storage;
	zend_mm_heap    *heap;
	//初始化storage
	storage = handlers->init(params);
	if (!storage) {
		fprintf(stderr, "Cannot initialize zend_mm storage [%s]\n", handlers->name);
		exit(255);
	}
	//设置handlers类库
	storage->handlers = handlers;

	heap = malloc(sizeof(struct _zend_mm_heap));
	if (heap == NULL) {
		fprintf(stderr, "Cannot allocate heap for zend_mm storage [%s]\n", handlers->name);
		exit(255);
	}

	heap->storage = storage;
	//内存块大小
	heap->block_size = block_size;
	heap->compact_size = 0;
	heap->segments_list = NULL;
	//初始化heap
	zend_mm_init(heap);

	heap->use_zend_alloc = 1;
	heap->real_size = 0;
	heap->overflow = 0;
	heap->real_peak = 0;
	heap->limit = ZEND_MM_LONG_CONST(1)<<(32-2);
	heap->size = 0;
	heap->peak = 0;
	heap->internal = internal;
	heap->reserve = NULL;
	heap->reserve_size = reserve_size;
	return heap;
}

static zend_mm_free_block *zend_mm_search_large_block(zend_mm_heap *heap, size_t true_size)
{
	zend_mm_free_block *best_fit;
	//计算对应的下标
	size_t index = ZEND_MM_LARGE_BUCKET_INDEX(true_size);
	size_t bitmap = heap->large_free_bitmap >> index;
	zend_mm_free_block *p;

	if (bitmap == 0) {
		return NULL;
	}

	if (UNEXPECTED((bitmap & 1) != 0)) {
		/* Search for best "large" free block */
		zend_mm_free_block *rst = NULL;
		size_t m;
		size_t best_size = -1;

		best_fit = NULL;
		p = heap->large_free_buckets[index];
		for (m = true_size << (32 - index); ; m <<= 1) {
			//如果free_buckets[index]当前的内存大小和true_size相等 则寻找结束, 成功返回。
			if (UNEXPECTED(ZEND_MM_FREE_BLOCK_SIZE(p) == true_size)) {
				return p->next_free_block;
			} else if (ZEND_MM_FREE_BLOCK_SIZE(p) >= true_size &&
			           ZEND_MM_FREE_BLOCK_SIZE(p) < best_size) {
				best_size = ZEND_MM_FREE_BLOCK_SIZE(p);
				best_fit = p;
			}
			if ((m & (ZEND_MM_LONG_CONST(1) << (32-1))) == 0) {
				if (p->child[1]) {
					rst = p->child[1];
				}
				if (p->child[0]) {
					p = p->child[0];
				} else {
					break;
				}
			} else if (p->child[1]) {
				p = p->child[1];
			} else {
				break;
			}
		}

		for (p = rst; p; p = p->child[p->child[0] != NULL]) {
			if (UNEXPECTED(ZEND_MM_FREE_BLOCK_SIZE(p) == true_size)) {
				return p->next_free_block;
			} else if (ZEND_MM_FREE_BLOCK_SIZE(p) > true_size &&
			           ZEND_MM_FREE_BLOCK_SIZE(p) < best_size) {
				best_size = ZEND_MM_FREE_BLOCK_SIZE(p);
				best_fit = p;
			}
		}

		if (best_fit) {
			return best_fit->next_free_block;
		}
		bitmap = bitmap >> 1;
		if (!bitmap) {
			return NULL;
		}
		index++;
	}

	/* Search for smallest "large" free block */
	best_fit = p = heap->large_free_buckets[index + zend_mm_low_bit(bitmap)];
	while ((p = p->child[p->child[0] != NULL])) {
		if (ZEND_MM_FREE_BLOCK_SIZE(p) < ZEND_MM_FREE_BLOCK_SIZE(best_fit)) {
			best_fit = p;
		}
	}
	return best_fit->next_free_block;
}

static inline void zend_mm_remove_from_free_list(zend_mm_heap *heap, zend_mm_free_block *mm_block)
{
	zend_mm_free_block *prev = mm_block->prev_free_block;
	zend_mm_free_block *next = mm_block->next_free_block;

	ZEND_MM_CHECK_MAGIC(mm_block, MEM_BLOCK_FREED);

	if (EXPECTED(prev == mm_block)) {
		zend_mm_free_block **rp, **cp;

		rp = &mm_block->child[mm_block->child[1] != NULL];
		prev = *rp;
		if (EXPECTED(prev == NULL)) {
			size_t index = ZEND_MM_LARGE_BUCKET_INDEX(ZEND_MM_FREE_BLOCK_SIZE(mm_block));

			ZEND_MM_CHECK_TREE(mm_block);
			*mm_block->parent = NULL;
			if (mm_block->parent == &heap->large_free_buckets[index]) {
				heap->large_free_bitmap &= ~(ZEND_MM_LONG_CONST(1) << index);
		    }
		} else {
			while (*(cp = &(prev->child[prev->child[1] != NULL])) != NULL) {
				prev = *cp;
				rp = cp;
			}
			*rp = NULL;

subst_block:
			ZEND_MM_CHECK_TREE(mm_block);
			*mm_block->parent = prev;
			prev->parent = mm_block->parent;
			if ((prev->child[0] = mm_block->child[0])) {
				ZEND_MM_CHECK_TREE(prev->child[0]);
				prev->child[0]->parent = &prev->child[0];
			}
			if ((prev->child[1] = mm_block->child[1])) {
				ZEND_MM_CHECK_TREE(prev->child[1]);
				prev->child[1]->parent = &prev->child[1];
			}
		}
	} else {
		printf("next:%d\n",next);
		printf("prev:%d\n",prev);
		prev->next_free_block = next;
		next->prev_free_block = prev;

		if (EXPECTED(ZEND_MM_SMALL_SIZE(ZEND_MM_FREE_BLOCK_SIZE(mm_block)))) {
			if (EXPECTED(prev == next)) {
				size_t index = ZEND_MM_BUCKET_INDEX(ZEND_MM_FREE_BLOCK_SIZE(mm_block));
				printf("free_buckets[index*2]:%d\n",heap->free_buckets[index*2]);
				printf("free_buckets[index*2+1]:%d\n",heap->free_buckets[index*2+1]);
				if (EXPECTED(heap->free_buckets[index*2] == heap->free_buckets[index*2+1])) {
					heap->free_bitmap &= ~(ZEND_MM_LONG_CONST(1) << index);
				}
			}
		} else if (UNEXPECTED(mm_block->parent != NULL)) {
			goto subst_block;
		}
	}
}

static inline void zend_mm_add_to_free_list(zend_mm_heap *heap, zend_mm_free_block *mm_block)
{
	size_t size;
	size_t index;

	ZEND_MM_SET_MAGIC(mm_block, MEM_BLOCK_FREED);

	size = ZEND_MM_FREE_BLOCK_SIZE(mm_block);
	if (EXPECTED(!ZEND_MM_SMALL_SIZE(size))) {
		zend_mm_free_block **p;
		//根据size获取对应的LARGE下标
		index = ZEND_MM_LARGE_BUCKET_INDEX(size);
		p = &heap->large_free_buckets[index];
		mm_block->child[0] = mm_block->child[1] = NULL;
		if (!*p) {
			*p = mm_block;
			mm_block->parent = p;
			mm_block->prev_free_block = mm_block->next_free_block = mm_block;
			heap->large_free_bitmap |= (ZEND_MM_LONG_CONST(1) << index);
		} else {
			size_t m;

			for (m = size << (32 - index); ; m <<= 1) {
				zend_mm_free_block *prev = *p;

				if (ZEND_MM_FREE_BLOCK_SIZE(prev) != size) {
					p = &prev->child[(m >> (32-1)) & 1];
					if (!*p) {
						*p = mm_block;
						mm_block->parent = p;
						mm_block->prev_free_block = mm_block->next_free_block = mm_block;
						break;
					}
				} else {
					zend_mm_free_block *next = prev->next_free_block;

					prev->next_free_block = next->prev_free_block = mm_block;
					mm_block->next_free_block = next;
					mm_block->prev_free_block = prev;
					mm_block->parent = NULL;
					break;
				}
			}
		}
	} else {
		//小块内存
		zend_mm_free_block *prev, *next;
		//根据size获取对应的下标
		index = ZEND_MM_BUCKET_INDEX(size);
		//获取index的 prev_free_block位置
		prev = ZEND_MM_SMALL_FREE_BUCKET(heap, index);
		printf("prev->prev_free_block:%d,prev:%d,size:%d\n",prev->prev_free_block,prev,size);
		if (prev->prev_free_block == prev) {
			printf("index:%d\n",index);
			//标志位
			heap->free_bitmap |= (ZEND_MM_LONG_CONST(1) << index);
		}
		next = prev->next_free_block;
		printf("prev->next_free_block:%d\n",prev->next_free_block);
		//设置mm_block指针指向
		mm_block->prev_free_block = prev;
		mm_block->next_free_block = next;
		printf("mm_block:%d,mm_block->prev_free_block:%d,mm_block->next_free_block:%d\n",mm_block,mm_block->prev_free_block,mm_block->next_free_block);
		prev->next_free_block = next->prev_free_block = mm_block;
		printf("prev->next_free_block:%d,next->prev_free_block:%d\n",prev->next_free_block,next->prev_free_block);
	}
}

static inline void zend_mm_add_to_rest_list(zend_mm_heap *heap, zend_mm_free_block *mm_block)
{
	zend_mm_free_block *prev, *next;

	ZEND_MM_SET_MAGIC(mm_block, MEM_BLOCK_FREED);

	if (!ZEND_MM_SMALL_SIZE(ZEND_MM_FREE_BLOCK_SIZE(mm_block))) {
		mm_block->parent = NULL;
	}

	prev = heap->rest_buckets[0];
	next = prev->next_free_block;
	mm_block->prev_free_block = prev;
	mm_block->next_free_block = next;
	prev->next_free_block = next->prev_free_block = mm_block;
}


static void *_zend_mm_alloc_int(zend_mm_heap *heap, size_t size)
{
	zend_mm_free_block *best_fit;
	size_t true_size = ZEND_MM_TRUE_SIZE(size);
	size_t block_size;
	size_t remaining_size;
	size_t segment_size;
	zend_mm_segment *segment;
	int keep_rest = 0;

	if (EXPECTED(ZEND_MM_SMALL_SIZE(true_size))) {
		size_t index = ZEND_MM_BUCKET_INDEX(true_size);
		size_t bitmap;

		if (UNEXPECTED(true_size < size)) {
			goto out_of_memory;
		}
		bitmap = heap->free_bitmap >> index;
		printf("index：%d,bitmap:%d\n", index,bitmap);
		if (bitmap) {
			/* Found some "small" free block that can be used */
			//寻找最适合的内存块下标
			index += zend_mm_low_bit(bitmap);
			best_fit = heap->free_buckets[index*2];
			goto zend_mm_finished_searching_for_block;
		}
	}

	best_fit = zend_mm_search_large_block(heap, true_size);

	if (!best_fit && heap->real_size >= heap->limit - heap->block_size) {
		zend_mm_free_block *p = heap->rest_buckets[0];
		size_t best_size = -1;

		while (p != ZEND_MM_REST_BUCKET(heap)) {
			if (UNEXPECTED(ZEND_MM_FREE_BLOCK_SIZE(p) == true_size)) {
				best_fit = p;
				goto zend_mm_finished_searching_for_block;
			} else if (ZEND_MM_FREE_BLOCK_SIZE(p) > true_size &&
			           ZEND_MM_FREE_BLOCK_SIZE(p) < best_size) {
				best_size = ZEND_MM_FREE_BLOCK_SIZE(p);
				best_fit = p;
			}
			p = p->prev_free_block;
		}
	}

	if (!best_fit) {
		if (true_size > heap->block_size - (ZEND_MM_ALIGNED_SEGMENT_SIZE + ZEND_MM_ALIGNED_HEADER_SIZE)) {
			/* Make sure we add a memory block which is big enough,
			   segment must have header "size" and trailer "guard" block */
			segment_size = true_size + ZEND_MM_ALIGNED_SEGMENT_SIZE + ZEND_MM_ALIGNED_HEADER_SIZE;
			segment_size = (segment_size + (heap->block_size-1)) & ~(heap->block_size-1);
			keep_rest = 1;
		} else {
			//默认block_size
			segment_size = heap->block_size;
		}

		if (segment_size < true_size ||
		    heap->real_size + segment_size > heap->limit) {
		}
		//申请一块内存
		segment = (zend_mm_segment *) ZEND_MM_STORAGE_ALLOC(segment_size);

		if (!segment) {
out_of_memory:
			printf("Out of memory (allocated %ld) (tried to allocate %lu bytes)", heap->real_size, size);
			return NULL;
		}
		//emalloc分配的内存大小
		heap->real_size += segment_size;
		if (heap->real_size > heap->real_peak) {
			heap->real_peak = heap->real_size;
		}
		//设置大小
		segment->size = segment_size;
		//将新元素放置表头
		segment->next_segment = heap->segments_list;
		//重置segments_list指向
		heap->segments_list = segment;

		best_fit = (zend_mm_free_block *) ((char *) segment + ZEND_MM_ALIGNED_SEGMENT_SIZE);
		//重置第一个zend_mm_free_block info._prev属性值
		ZEND_MM_MARK_FIRST_BLOCK(best_fit);

		block_size = segment_size - ZEND_MM_ALIGNED_SEGMENT_SIZE - ZEND_MM_ALIGNED_HEADER_SIZE;
		//设置最后一个zend_mm_block info.size
		ZEND_MM_LAST_BLOCK(ZEND_MM_BLOCK_AT(best_fit, block_size));

		printf("---new:%d----\n",segment_size);
		
	} else {
zend_mm_finished_searching_for_block:
		/* remove from free list */
		
		//从list移除best_fit,稍后best_fit空间会发生变化
		zend_mm_remove_from_free_list(heap, best_fit);
		//获取剩余空间大小
		block_size = ZEND_MM_FREE_BLOCK_SIZE(best_fit);
	}
	//剩余大小
	remaining_size = block_size - true_size;
	printf("ZEND_MM_MAX_SMALL_SIZE:%d\n",ZEND_MM_MAX_SMALL_SIZE);
	printf("true_size:%d\n",true_size);
	printf("block_size:%d\n",block_size);
	printf("remaining_size:%d\n",remaining_size);
	//分配后的空间<ZEND_MM_ALIGNED_MIN_HEADER_SIZE，则表明不足以分配一个block。
	if (remaining_size < ZEND_MM_ALIGNED_MIN_HEADER_SIZE) {
		true_size = block_size;
		ZEND_MM_BLOCK(best_fit, ZEND_MM_USED_BLOCK, true_size);
	} else {
		zend_mm_free_block *new_free_block;

		/* prepare new free block */
		//准备一块新内存
		ZEND_MM_BLOCK(best_fit, ZEND_MM_USED_BLOCK, true_size);
		new_free_block = (zend_mm_free_block *) ZEND_MM_BLOCK_AT(best_fit, true_size);
		ZEND_MM_BLOCK(new_free_block, ZEND_MM_FREE_BLOCK, remaining_size);

		/* add the new free block to the free list */
		if (EXPECTED(!keep_rest)) {
			//添加到free列表中
			zend_mm_add_to_free_list(heap, new_free_block);
		} else {
			zend_mm_add_to_rest_list(heap, new_free_block);
		}
	}

	ZEND_MM_SET_DEBUG_INFO(best_fit, size, 1, 1);
	//记录系统分配的内存大小
	heap->size += true_size;
	//记录系统分配的峰值
	if (heap->peak < heap->size) {
		heap->peak = heap->size;
	}
	return ZEND_MM_DATA_OF(best_fit);
}




int main(void){
	zend_mm_heap *heap;
	const zend_mm_mem_handlers *handlers;
	handlers = &mem_handlers[0];
	heap = zend_mm_startup_ex(handlers, 512, 0, 0, NULL);

	_zend_mm_alloc_int(heap,256);
	_zend_mm_alloc_int(heap,256);
	_zend_mm_alloc_int(heap,128);
	_zend_mm_alloc_int(heap,128);
	//_zend_mm_alloc_int(heap,256);
	//_zend_mm_alloc_int(heap,234);
	//_zend_mm_alloc_int(heap,256);
	//_zend_mm_alloc_int(heap,230);
	//_zend_mm_alloc_int(heap,200);
	return 0;
}
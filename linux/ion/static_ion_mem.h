#ifndef STATIC_ION_MEM_H
#define STATIC_ION_MEM_H
#include <linux/types.h>

#define ION_MEM_MAX_SIZE 10

struct register_ion_mem_tag {
	uint32_t size;
	uint64_t memaddr[ION_MEM_MAX_SIZE];
	uint32_t memsize[ION_MEM_MAX_SIZE];
	uint32_t memtag[ION_MEM_MAX_SIZE];
};

enum static_mem_tag {
	MEM_TAG_MIN = 0,
	PP_MEM_TAG = 1,
	PRI_PP_MEM_TAG = 2,
	PT_MEM_TAG = 3,
	MEM_TAG_MAX,
};

#ifdef CONFIG_STATIC_ION
int tc_ns_register_ion_mem(void);
#else
static inline int tc_ns_register_ion_mem(void)
{
	return 0;
}
#endif

#endif
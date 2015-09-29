#ifndef GEEKOS_USERVM_H

int Alloc_Pages_User(pde_t *pageDir,uint_t startAddress,uint_t sizeInMemory);
uint_t g_freePagecount;

#endif

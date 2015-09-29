/*
 * Physical memory allocation
 * Copyright (c) 2001,2003,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * Copyright (c) 2003,2013,2014 Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 *
 * All rights reserved.
 *
 * This code may not be resdistributed without the permission of the copyright holders.
 * Any student solutions using any of this code base constitute derviced work and may
 * not be redistributed in any form.  This includes (but is not limited to) posting on
 * public forums or web sites, providing copies to (past, present, or future) students
 * enrolled in similar operating systems courses the University of Maryland's CMSC412 course.
 *
 * $Revision: 1.45 $
 * 
 */

#include <geekos/defs.h>
#include <geekos/ktypes.h>
#include <geekos/kassert.h>
#include <geekos/kthread.h>
#include <geekos/bootinfo.h>
#include <geekos/gdt.h>
#include <geekos/screen.h>
#include <geekos/int.h>
#include <geekos/malloc.h>
#include <geekos/string.h>
#include <geekos/paging.h>
#include <geekos/mem.h>

/* ----------------------------------------------------------------------
 * Global data
 * ---------------------------------------------------------------------- */

/*
 * List of Page structures representing each page of physical memory.
 */
struct Page *g_pageList;

/*
 * Number of pages currently available on the freelist.
 */
uint_t g_freePageCount = 0;
int pages_count = 0;
/* ----------------------------------------------------------------------
 * Private data and functions
 * ---------------------------------------------------------------------- */

/*
 * Defined in paging.c
 */
extern int debugFaults;
#define Debug(args...) if (debugFaults) Print(args)

/*
 * Add a range of pages to the inventory of physical memory.
 */
static void Add_Page_Range(ulong_t start, ulong_t end, int flags) {
    ulong_t addr;
    KASSERT(Is_Page_Multiple(start));
    KASSERT(Is_Page_Multiple(end));
    KASSERT(start < end);
    
    for (addr = start; addr < end; addr += PAGE_SIZE) {
        struct Page *page = Get_Page(addr);

        page->flags = flags;

        if (flags == PAGE_AVAIL) {
				//Print("Page added is %x\n", (unsigned int)Get_Page_Address(page));
            /* Add the page to the freelist */
            Unchecked_Add_To_Back_Of_Page_List(&s_freeList, page);
            /* Update free page count */
            ++g_freePageCount;
        } else {
            Set_Next_In_Page_List(page, 0);
            Set_Prev_In_Page_List(page, 0);
        }

        page->clock = 0;
        page->vaddr = 0;
        page->context = NULL;
        page->entry = 0;
    }

}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

/*
 * The linker defines this symbol to indicate the end of
 * the executable image.
 */
extern char end;

/*
 * Initialize memory management data structures.
 * Enables the use of Alloc_Page() and Free_Page() functions.
 */
void Init_Mem(struct Boot_Info *bootInfo) {
    if (!bootInfo->memSizeKB) {
        /* look through memsize for a region starting at 0x100000 */
        int i;

        for (i = 0; i < bootInfo->numMemRegions; i++) {
            if ((bootInfo->memRegions[i].baseAddr_low == 0x100000) &&
                (bootInfo->memRegions[i].type == 1)) {
                bootInfo->memSizeKB =
                    bootInfo->memRegions[i].length_low / 1024;
            }
        }
        bootInfo->memSizeKB += 0x1000;
    }

    ulong_t numPages = bootInfo->memSizeKB >> 2;
    ulong_t endOfMem = numPages * PAGE_SIZE;
    unsigned numPageListBytes = sizeof(struct Page) * numPages;
    ulong_t pageListAddr;
    ulong_t kernEnd;
    ulong_t pageListEnd;

    KASSERT(bootInfo->memSizeKB > 0);

    /*
     * Before we do anything, switch from setup.asm's temporary GDT
     * to the kernel's permanent GDT.
     */
    Init_GDT(0);

    /*
     * We'll put the list of Page objects right after the end
     * of the kernel, and mark it as "kernel".  This will bootstrap
     * us sufficiently that we can start allocating pages and
     * keeping track of them.
     */
    pageListAddr = (HIGHMEM_START + KERNEL_HEAP_SIZE);
    if (pageListAddr >= endOfMem) {
        Print
            ("there is no memory for the page list.  physical memory is too small for the heap %u, bytes after %u. endOfMem=%lu .",
             KERNEL_HEAP_SIZE, HIGHMEM_START, endOfMem);
        KASSERT0(pageListAddr < endOfMem,
                 "there is no memory for the page list.  physical memory is too small for the heap.");
    }
    g_pageList = (struct Page *)pageListAddr;
    pageListEnd = Round_Up_To_Page(pageListAddr + numPageListBytes);

    // clear page list
    memset((void *)g_pageList, '\0', (pageListEnd - (ulong_t) g_pageList));

    kernEnd = Round_Up_To_Page((int)&end);
    s_numPages = numPages;

    /*
     * The initial kernel thread and its stack are placed
     * just beyond the ISA hole.
     */
    KASSERT(ISA_HOLE_END == KERN_THREAD_OBJ);
    KASSERT(KERN_STACK == KERN_THREAD_OBJ + PAGE_SIZE);

    /*
     * Memory looks like this:
     * 0 - start: available (might want to preserve BIOS data area)
     * start - end: kernel
     * end - ISA_HOLE_START: available
     * ISA_HOLE_START - ISA_HOLE_END: used by hardware (and ROM BIOS?)
     * ISA_HOLE_END - HIGHMEM_START: used by initial kernel thread
     * HIGHMEM_START - end of memory: available
     *    (the kernel heap is located at HIGHMEM_START; any unused memory
     *    beyond that is added to the freelist)
     */

    Add_Page_Range(0, PAGE_SIZE, PAGE_UNUSED);
    Add_Page_Range(PAGE_SIZE, KERNEL_START_ADDR, PAGE_AVAIL);
    Add_Page_Range(KERNEL_START_ADDR, kernEnd, PAGE_KERN);
    Add_Page_Range(kernEnd, ISA_HOLE_START, PAGE_AVAIL);
    Add_Page_Range(ISA_HOLE_START, ISA_HOLE_END, PAGE_HW);
    Add_Page_Range(ISA_HOLE_END, HIGHMEM_START, PAGE_ALLOCATED);
    Add_Page_Range(HIGHMEM_START, HIGHMEM_START + KERNEL_HEAP_SIZE,
                   PAGE_HEAP);
    Add_Page_Range(pageListAddr, pageListEnd, PAGE_KERN);
    if (pageListEnd > endOfMem) {
        KASSERT0(pageListEnd < endOfMem,
                 "there is no memory after the page list.  physical memory is too small.");
        /* this would fail at the next line (add_page_range), so this kassert just fails early. */
    }
    Add_Page_Range(pageListEnd, endOfMem, PAGE_AVAIL);

    /* Initialize the kernel heap */
    Init_Heap(HIGHMEM_START, KERNEL_HEAP_SIZE);
    Print
        ("%uKB memory detected, %u pages in freelist, %d bytes in kernel heap\n",
         bootInfo->memSizeKB, g_freePageCount, KERNEL_HEAP_SIZE);

    Init_Clock();

}

/*
 * Initialize the clock hand pointers
 */
void Init_Clock(void) {
    hand2 = HANDS_DIST;
    hand1 = 0;
}

/*
 * Initialize the .bss section of the kernel executable image.
 */
void Init_BSS(void) {
    extern char BSS_START, BSS_END;

    /* Fill .bss with zeroes */
    memset(&BSS_START, '\0', &BSS_END - &BSS_START);
}

bool check() {
    struct Page_List s_freeList2 = s_freeList;
    
    struct Page_List s_freeList3 = s_freeList;
    struct Page_List *temp = &s_freeList2;
    unsigned int h, i;
    int gh=0;
    for(; !Is_Page_List_Empty(temp); Remove_From_Front_Of_Page_List(temp)) {
        gh++;
         if(gh<3)
         Print("progress"); 
        if(Is_Member_Of2_Page_List(&s_freeList2, temp->head)){
            Print("Double occurrence\n");
            int i;
            break;
            for(i=0; i<1000000000; i++);
        }
        //s_freeList3 = s_freeList2;
        //int kl=0;
        //struct Page_List *temp2 = &s_freeList3;
        //if(Is_Page_List_Empty(temp2)) continue;
        //Remove_From_Front_Of_Page_List(temp2);  

        //temp2->head = temp->head->nextPage_List;
        /*for(; !Is_Page_List_Empty(temp2); Remove_From_Front_Of_Page_List(temp2)) {
            kl++;
            if((unsigned int)Get_Page_Address(temp->head)==(unsigned int)Get_Page_Address(temp2->head)) {
                Print("Wrong %d %x %x\n", kl, (unsigned int)Get_Page_Address(temp->head), (unsigned int)Get_Page_Address(temp2->head));
                int j;
                //for(j=0;j<1000000000;j++) ;
            }*/
        //}
    }

    return true;
}

static void *Alloc_Page_Frame(void) {
    struct Page *page, *page2;
    void *result = 0;

    /* See if we have a free page */
    if (!Is_Page_List_Empty(&s_freeList) && pages_count < 2000) {
        pages_count++;
        // Print("pages count = %i\n", pages_count);
        /* Remove the first page on the freelist. */
        page = Get_Front_Of_Page_List(&s_freeList);
        //Print("is pageable? %d\n", page->flags & PAGE_PAGEABLE);

        //Print("trying to allocate: %x %p %p\n", (unsigned int)page->vaddr, page, (void *)Get_Page_Address(page));
        //Print("Page allocated is %lu\n", page->vaddr);
        /*if((page->flags & PAGE_ALLOCATED) != 0) {
            result=0;
            goto x;
        }*/
            //if(!((page->flags & PAGE_ALLOCATED) == 0))
              // { Print("backchodhi\n");check();}

        KASSERT((page->flags & PAGE_ALLOCATED) == 0);
        Remove_From_Front_Of_Page_List(&s_freeList);
    /*
	while(Get_Page_Address(Get_Front_Of_Page_List(&s_freeList))==Get_Page_Address(page)) {
        //Print("head is at %x\n", (unsigned int)s_freeList.head);
		//Print("addr: %x\n", (unsigned int)Get_Page_Address(Get_Front_Of_Page_List(&s_freeList)));
        Remove_From_Front_Of_Page_List(&s_freeList);
    }
    */

        //page2 = Get_Front_Of_Page_List(&s_freeList);
        //Print("Repeat: Page allocated is %lu\n", page->vaddr);

        //Print("Next is %p\n", Get_Front_Of_Page_List(&s_freeList));
        /* Mark page as having been allocated. */
        page->flags |= PAGE_ALLOCATED;
        g_freePageCount--;
        Wake_Up(&g_ffmWaitQueue);
        result = (void *)Get_Page_Address(page);

    }
//x:
    if (result) {
        memset(result, '\0', 4096);
    }
    //if((unsigned int)result==0x002fc000) {
        //Print("--------------yes--------- %p\n", result);
        //Print("Next is %p\n", Get_Front_Of_Page_List(&s_freeList));
    //}
    //Print("allocated %x\n", (int)result);
    return result;
}

/*
 * Choose a page to evict.
 * Returns null if no pages are available.
 */
static struct Page *Find_Page_To_Page_Out() {
    struct Page *best = 0;
    bool found = false;
    //while(true)
    //    Print("called called \n");
    int count1 = 0;
    while(!found) {
        count1++;
        struct Page *p1 = &g_pageList[hand1], *p2 = &g_pageList[hand2];
        if(!(p1->flags & PAGE_ALLOCATED) || p1->entry == 0 || p1->entry->present == 0){
        hand1 = (hand1 + 1) % s_numPages;
        hand2 = (hand2 + 1) % s_numPages;
            continue;}

        Print("p1 = %p p2 = %p\n", p1, p2);
        Print("p1 = %u p2 = %u\n", hand1, hand2);
      //  KASSERT0(!(int)p1->entry,"Page table entry is missing \n ");
        Print("entry->accessed = %i \n", (int)p1->entry->accessed);
        Print("entry->pageable = %i \n", (int)(p1->flags & PAGE_PAGEABLE));
        
         Print("entry->allocated = %i \n", (int)(p1->flags & PAGE_ALLOCATED));
        if (
            ! p1->entry->accessed && 
            (p1->flags & PAGE_PAGEABLE) &&
            (p1->flags & PAGE_ALLOCATED)
            ) 
        {
            best = p1;
            Print("Found a page \n");
            found = true;
        }
        // Print("clock replacement\n");
        if(p2->entry != 0)
        p2->entry->accessed = (char)0;
        hand1 = (hand1 + 1) % s_numPages;
        hand2 = (hand2 + 1) % s_numPages;
         // Print("clock replacement yo\n");
        // if (count1 % 1000 == 0)
            
    }
    return best;
}


/**
 * Allocate a page of pageable physical memory, to be mapped
 * into a user address space.
 *
 * @param entry pointer to user page table entry which will
 *   refer to the allocated page
 * @param vaddr virtual address where page will be mapped
 *   in user address space
 */
static void *Alloc_Or_Reclaim_Page(pte_t * entry, ulong_t vaddr,
                                   bool pinnedPage) {
    bool iflag;
    bool mappedPage;
    void *paddr = 0;
    struct Page *page = 0;

    iflag = Begin_Int_Atomic();

    KASSERT(!Interrupts_Enabled());
    KASSERT(Is_Page_Multiple(vaddr));

    paddr = Alloc_Page_Frame();
    if (paddr != 0) {
        page = Get_Page((ulong_t) paddr);
        //Print("is pageable? %d\n", page->flags & PAGE_PAGEABLE);

        KASSERT((page->flags & PAGE_PAGEABLE) == 0);
    } else {

        int pagefileIndex;
        /* Select a page to steal from another process */
        Debug("About to hunt for a page to page out\n");
        page = Find_Page_To_Page_Out();
        //Print("is pageable? %d\n", page->flags & PAGE_PAGEABLE);
        KASSERT(page->flags & PAGE_PAGEABLE);

        paddr = (void *)Get_Page_Address(page);
        Debug("Selected page at addr %p (age = %d)\n", paddr, page->clock);

        /* Make the page temporarily unpageable (can't let another process steal it) */
        page->flags &= ~(PAGE_PAGEABLE);

        /* Lock the page so it cannot be freed while we're writing */
        page->flags |= PAGE_LOCKED;
        Print("trying to evict\n");
        /* check if it is an mmap'd page */
        if (Is_Mmaped_Page(page->context, page->vaddr)) {
            mappedPage = true;
            if (page->entry->dirty) {
                Enable_Interrupts();
                Write_Out_Mmaped_Page(page->context, page->vaddr);
                Disable_Interrupts();
                page->entry->dirty = 0;
            }
            page->entry->present = 0;
        } else {
            mappedPage = false;

            /* Find a place on disk for the page (if there isn't space, we're screwed.) */
            pagefileIndex = Find_Space_On_Paging_File();
            if (pagefileIndex < 0) {
                /* No space available in paging file. */
                KASSERT0(paddr == NULL,
                         "expected to return NULL when no space on the paging file.");
                goto done;
            }
            Debug("Free disk page at index %d\n", pagefileIndex);

            /* Write the page to disk. Interrupts are enabled, since the I/O may block. */
            Debug("Writing physical frame %p to paging file at %d\n", paddr,
                  pagefileIndex);
            Enable_Interrupts();
            Write_To_Paging_File(paddr, page->vaddr, pagefileIndex);
            Disable_Interrupts();
            Print("Paging out\n");

            Debug("Wrote physical frame %p to paging file at %d\n", paddr,
                  pagefileIndex);
        }

        /* While we were writing got notification this page isn't even needed anymore */
        if (page->flags & PAGE_ALLOCATED) {
            /* The page is still in use update its bookeping info */
            /* Update page table to reflect the page being on disk */
            page->entry->present = 0;
            if (!mappedPage) {
                page->entry->kernelInfo = KINFO_PAGE_ON_DISK;
                page->entry->pageBaseAddr = pagefileIndex;      /* Remember where it is located! */
            }
        } else {
            /* The page got freed, don't need bookeeping or it on disk */
            if (!mappedPage) {
                Free_Space_On_Paging_File(pagefileIndex);
            }

            /* Its still allocated though to us now */
            page->flags |= PAGE_ALLOCATED;
        }

        /* Unlock the page */
        page->flags &= ~(PAGE_LOCKED);

        /* XXX - flush TLB should only flush the one page */
        Flush_TLB();
    }

    /* Fill in accounting information for page */
    if (pinnedPage) {
        page->flags |= PAGE_LOCKED;
        page->entry = NULL;
        page->vaddr = 0;
        page->context = NULL;
    } else {
        page->flags |= PAGE_PAGEABLE;
        page->entry = entry;
        page->entry->kernelInfo = 0;
        page->vaddr = vaddr;
        page->context = CURRENT_THREAD->userContext;
        KASSERT(page->flags & PAGE_ALLOCATED);
    }

  done:
    End_Int_Atomic(iflag);
    return paddr;
}

/*
 * Allocate a pinned (non-pageable) page of physical memory.
 */
void *Alloc_Page(void) {
    void *ret;

    ret = Alloc_Or_Reclaim_Page(NULL, 0, true);
    if (!ret) {
        // Print("Kernel Memory Exhausted, shutting down\n");
        extern void Hardware_Shutdown();
        Hardware_Shutdown();
    }

    return ret;
}

/**
 * Allocate a page of pageable physical memory, to be mapped
 * into a user address space.
 *
 * @param entry pointer to user page table entry which will
 *   refer to the allocated page
 * @param vaddr virtual address where page will be mapped
 *   in user address space
 */
void *Alloc_Pageable_Page(pte_t * entry, ulong_t vaddr) {
    return Alloc_Or_Reclaim_Page(entry, vaddr, false);
}

/*
 * Free a page of physical memory.
 */
void Free_Page(void *pageAddr) {

    ulong_t addr = (ulong_t) pageAddr;
    struct Page *page;

    memset(pageAddr, '\0', 4096);

    KASSERT(Is_Page_Multiple(addr));

    /* Get the Page object for this page */
    page = Get_Page(addr);
    KASSERT0(page, "Couldn't find a struct Page * for the given pageAddr");     /* should be impossible */

    KASSERT0((page->flags & PAGE_ALLOCATED) != 0,
             "Expected Free_Page parameter to have been allocated.");

    /* Clear the allocation bit */
    page->flags &= ~(PAGE_ALLOCATED);

    /* When a page is locked, don't free it just let other thread know its not needed */
    if (page->flags & PAGE_LOCKED)
        return;

    /* Clear the pageable bit */
    page->flags &= ~(PAGE_PAGEABLE);

    /* clear the PTE this used to refer to */
    page->entry = 0;

    /* Put the page back on the freelist */
    Add_To_Back_Of_Page_List(&s_freeList, page);
    g_freePageCount++;

}


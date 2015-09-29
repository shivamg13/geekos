/*
 * Paging (virtual memory) support
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
 * $Revision: 1.56 $
 *
 */

#include <geekos/string.h>
#include <geekos/int.h>
#include <geekos/idt.h>
#include <geekos/kthread.h>
#include <geekos/kassert.h>
#include <geekos/screen.h>
#include <geekos/mem.h>
#include <geekos/debug.h>
#include <geekos/malloc.h>
#include <geekos/gdt.h>
#include <geekos/segment.h>
#include <geekos/user.h>
#include <geekos/vfs.h>
#include <geekos/crc32.h>
#include <geekos/paging.h>
#include <geekos/errno.h>
#include <geekos/projects.h>
#include <geekos/smp.h>
#include <geekos/uservm.h>

#include <libc/mmap.h>
/* ----------------------------------------------------------------------
 * Public data
 * ---------------------------------------------------------------------- */

/* ----------------------------------------------------------------------
 * Private functions/data
 * ---------------------------------------------------------------------- */

#define SECTORS_PER_PAGE (PAGE_SIZE / SECTOR_SIZE)

/*
 * flag to indicate if debugging paging code
 */
int debugFaults = 0;

#define Debug(args...) if (debugFaults) Print(args)


const pde_t *Kernel_Page_Dir(void) {
    /* 	TODO_P(PROJECT_VIRTUAL_MEMORY_A,
     "return kernel page directory and page tables");
     return NULL;*/
    return PageDir;
}

void Check_flags(void* pageDirectory, void *paddr,  unsigned int size) {
    struct Page * page = Get_Page((ulong_t) paddr);

    KASSERT0(!page, "Page struct not found\n");
    KASSERT0(!page->entry, "Page entry not found\n");
    
    KASSERT0(! (page->flags & PAGE_PAGEABLE), "Page not pageable\n");
    KASSERT0( (page->flags & PAGE_LOCKED), "Page is locked\n");
}


/*
 * Print diagnostic information for a page fault.
 */
static void Print_Fault_Info(uint_t address, faultcode_t faultCode) {
    extern uint_t g_freePageCount;
    
    Print("Pid %d: ", CURRENT_THREAD->pid);
    Print("\n Page Fault received, at address %p (%d pages free)\n",
          (void *)address, g_freePageCount);
    if (faultCode.protectionViolation)
        Print("   Protection Violation, ");
    else
        Print("   Non-present page, ");
    if (faultCode.writeFault)
        Print("Write Fault, ");
    else
        Print("Read Fault, ");
    if (faultCode.userModeFault)
        Print("in User Mode\n");
    else
        Print("in Supervisor Mode\n");
}

int read_count = 0;

/*
 * Handler for page faults.
 * You should call the Install_Interrupt_Handler() function to
 * register this function as the handler for interrupt 14.
 */
/*static*/ void Page_Fault_Handler(struct Interrupt_State *state) {
    ulong_t address;
    faultcode_t faultCode;
    
    KASSERT(!Interrupts_Enabled());
    
    /* Get the address that caused the page fault */
    address = Get_Page_Fault_Address();
    Debug("Page fault @%lx\n", address);
    
    if (address < 0xfec01000 && address > 0xf0000000) {
        KASSERT0(0, "page fault address in APIC/IOAPIC range\n");
    }
   
    /* Get the fault code */
    faultCode = *((faultcode_t *) & (state->errorCode));
    
    /* rest of your handling code here */
    TODO_P(PROJECT_VIRTUAL_MEMORY_B, "handle page faults");

    // mycode
    struct User_Context* userContext = CURRENT_THREAD->userContext;
    
    //in case of a write fault, allocate a new page
    if(faultCode.writeFault)
    {
        Print("write fault! \n");
        ulong_t page_dir_addr=address >> 22;
        ulong_t page_addr=(address << 10) >> 22;
        pde_t * page_dir_entry=(pde_t*)userContext->pageDir+page_dir_addr;
        pte_t * page_entry= NULL;

        if(page_dir_entry->present)
        {
            page_entry=(pte_t*)((page_dir_entry->pageTableBaseAddr) << 12);
            page_entry+=page_addr;
            if(page_entry->kernelInfo & KINFO_PAGE_ON_DISK)
            {
                int pagefile_index = page_entry->pageBaseAddr;
                void * paddr=Alloc_Pageable_Page(page_entry,Round_Down_To_Page(address));
                if(paddr==NULL)
                {
                    Print("no more page! ");
                    Print("-----here4\n");
                    goto error;
                }

                *((uint_t*)page_entry)=0;
                page_entry->present=1;
                //do we need to set these flags ????
                page_entry->kernelInfo &= ~(KINFO_PAGE_ON_DISK);
                page_entry->flags=VM_WRITE | VM_READ | VM_USER;
                page_entry->globalPage = 0;
                page_entry->pageBaseAddr = (ulong_t)paddr>>12;
                Enable_Interrupts();
                Read_From_Paging_File(paddr,Round_Down_To_Page(address), pagefile_index);
                Disable_Interrupts();
                Free_Space_On_Paging_File(pagefile_index);
                return ;
            }
        }    
        //if no page directory present 
        int result;
        result = Alloc_Pages_User(userContext->pageDir,Round_Down_To_Page(address),PAGE_SIZE);
        if(result==-1)
        {
            Print("cannot Allocate a page in page fault handler");
            Print("-----here1\n");
            goto error;
        }
        return;
    }
    else
    {
        // if(TEST_READ_FAULTS)
        //     Print("Read Fault! Paged in %x\n", (unsigned int)address);
        ulong_t page_dir_addr=address >> 22;
        ulong_t page_addr=(address << 10) >> 22;
        pde_t * page_dir_entry=(pde_t*)userContext->pageDir+page_dir_addr;
        pte_t * page_entry= NULL;

        if(page_dir_entry->present)
        {
            page_entry=(pte_t*)((page_dir_entry->pageTableBaseAddr) << 12);
            page_entry+=page_addr;
        }
        else
        {
            Print("-----here2\n");
            goto error;
        }

        //didnt understand this
        if(page_entry->kernelInfo!=KINFO_PAGE_ON_DISK)
        {
            //Illegal address access to the missing page case
            Print("-----here3, %x\n", (uint_t)address);
            goto error;
        }

        int pagefile_index = page_entry->pageBaseAddr;
        void * paddr=Alloc_Pageable_Page(page_entry,Round_Down_To_Page(address));
        if(paddr==NULL)
        {
            Print("no more page/n");
            Print("-----here4\n");
            goto error;
        }

        *((uint_t*)page_entry)=0;
        page_entry->present=1;
        //do we need to set these flags ????
        page_entry->kernelInfo &= ~(KINFO_PAGE_ON_DISK);
        page_entry->flags=VM_WRITE | VM_READ | VM_USER;
        page_entry->globalPage = 0;
        page_entry->pageBaseAddr = (ulong_t)paddr>>12;
        Enable_Interrupts();
        Read_From_Paging_File(paddr,Round_Down_To_Page(address), pagefile_index);
        Disable_Interrupts();
        Free_Space_On_Paging_File(pagefile_index);
        return ;
    }
    
    Print("Looking for %lu\n", address);

    TODO_P(PROJECT_MMAP, "handle mmap'd page faults");
    
    
error:
    Print("Unexpected Page Fault received\n");
    Print_Fault_Info(address, faultCode);
    Dump_Interrupt_State(state);
    /* user faults just kill the process */
    if (!faultCode.userModeFault)
        KASSERT0(0, "unhandled kernel-mode page fault.");
    
    /* For now, just kill the thread/process. */
    Exit(-1);
}

void Idenity_Map_Page(pde_t * currentPageDir, unsigned int address, int flags) {
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */


/*
 * Initialize virtual memory by building page tables
 * for the kernel and physical memory.
 */
void Init_VM(struct Boot_Info *bootInfo) {
    /*
     * Hints:
     * - Build kernel page directory and page tables
     * - Call Enable_Paging() with the kernel page directory
     * - Install an interrupt handler for interrupt 14,
     *   page fault
     * - Do not map a page at address 0; this will help trap
     *   null pointer references
     */
    ulong_t numPages = bootInfo->memSizeKB >> 2;
    //ulong_t numPages = 1024*1024;
    Print("Num pages = %lu\n", numPages);
    ulong_t numPdEnt = numPages/NUM_PAGE_TABLE_ENTRIES;
    
    PageDir=Alloc_Page();
    memset(PageDir, '\0', 4096);
    
    if(numPages%NUM_PAGE_TABLE_ENTRIES!=0)
    {
        numPdEnt++;
    }
    
    Print("Initializing Virtual Memory... \n");
    /*Install  page directory entries*/
    uint_t i,j;
    for(i=0;i<numPdEnt;i++){
        pde_t entry = {0};
        pte_t *pageTable;
        /* Allocate a page table and clear it */
        pageTable = Alloc_Page();
        memset(pageTable, '\0', 4096);
        
        /* Create a page directory entry pointing to this page table */
        entry.present = 1;
        entry.pageTableBaseAddr = ((ulong_t) pageTable) >> 12;
        entry.flags = VM_WRITE;
        
        /* Install the PDE in index i of the page directory */
        PageDir[i] = entry;
    }
    
    for(i=numPdEnt;i<NUM_PAGE_DIR_ENTRIES;i++){
        /* present bit is set to 0 */
        pde_t entry = {0};
        PageDir[i] = entry;
    }
    
    //Map APIC and IO APIC
    pde_t entry = {0};
    pte_t *pageTable;
    /* Allocate a page table and clear it */
    pageTable = Alloc_Page();
    memset(pageTable, '\0', 4096);
    
    /* Create a page directory entry pointing to this page table */
    entry.present = 1;
    entry.pageTableBaseAddr = ((ulong_t) pageTable) >> 12;
    entry.flags =  VM_WRITE;
    
    /* Install the PDE in index i of the page directory */
    
    
    for(j=0;j<256;j++){
        /*Case when number of pages in memory is not a multiple of NUM_PAGE_TABLE_ENTRIES*/
        
     			pte_t entry = {0};
     			ulong_t addr;
        /* Create a page table entry pointing to  physical memory frame*/
     			entry.present = 1;
     			entry.flags =  VM_WRITE;
     			addr=1019 << 10;
     			addr=addr | ((ulong_t) j);
     			entry.pageBaseAddr = addr;
        //Print("Address is %x \n", entry.pageBaseAddr);
        /* Install the PDE in index i of the page directory */
     			pageTable[j] = entry;
        
    }
    for(j=512;j<768;j++){
        /*Case when number of pages in memory is not a multiple of NUM_PAGE_TABLE_ENTRIES*/
        
     			pte_t entry = {0};
     			ulong_t addr;
        /* Create a page table entry pointing to  physical memory frame*/
     			entry.present = 1;
     			entry.flags =  VM_WRITE;
     			addr=1019 << 10;
     			addr=addr | ((ulong_t) j);
     			entry.pageBaseAddr = addr;
        //Print("Address is %x \n", entry.pageBaseAddr);
        /* Install the PDE in index i of the page directory */
     			pageTable[j] = entry;
        
    }
    PageDir[1019] = entry;
    //Map APIC and IO APIC
    
    /*Install  page table entries*/
    for(i=0;i<numPdEnt;i++){
        pte_t *PageTable = (pte_t *) (PageDir[i].pageTableBaseAddr << 12);
        
        for(j=0;j<NUM_PAGE_TABLE_ENTRIES;j++){
            /*Case when number of pages in memory is not a multiple of NUM_PAGE_TABLE_ENTRIES*/
            if(numPages%NUM_PAGE_TABLE_ENTRIES!=0 && i==numPdEnt-1 && j==(numPages%NUM_PAGE_TABLE_ENTRIES)){
                break;
            }
            else if (i==0 && j==0)
            {
                pte_t entry = {0};
                PageTable[j] = entry;
                continue;
            }
            else{
                
                pte_t entry = {0};
                ulong_t addr;
                /* Create a page table entry pointing to  physical memory frame*/
                entry.present = 1;
                entry.flags = VM_WRITE;
                addr=((ulong_t) i) << 10;
                addr=addr | ((ulong_t) j);
                entry.pageBaseAddr = addr;
                //Print("Address is %x \n", entry.pageBaseAddr);
                /* Install the PDE in index i of the page directory */
                PageTable[j] = entry;
            }
        }
    }
    
    /*Turn on paging*/
    Enable_Paging(PageDir);
    
    /* Install page fault handler */
    Install_Interrupt_Handler(14, Page_Fault_Handler);
    Install_Interrupt_Handler(46, Page_Fault_Handler);
    
    //Start_Kernel_Thread(Free_Frames_Manager, 0, PRIORITY_NORMAL, true, "{Free Frames Manager}");
    
}

void Init_Secondary_VM() {
    TODO_P(PROJECT_VIRTUAL_MEMORY_A, "enable paging on secondary cores");
}

/**
 * Initialize paging file data structures.
 * All filesystems should be mounted before this function
 * is called, to ensure that the paging file is available.
 */
void Init_Pagefile(void) {
    // list of free pages in pagefile
    int i;
    Print("Initializing Pagefile...\n");
    for(i = 0; i < BITMAP_SIZE; i++) {
        Free_BitMap[i] = 0xFFFFFFFF;
    }
    
    // initialize the mapping (empty)
    memset(PF_Map, -1, sizeof(ulong_t) * 33504);
    
    // open the block device for paging file
    // Open_Block_Device("ide1",&pdev);
    pdev = Get_Paging_Device()->dev;
    
    
    // TODO_P(PROJECT_VIRTUAL_MEMORY_B,
    //  "Initialize paging file data structures");
}

/**
 * Find a free bit of disk on the paging file for this page.
 * Interrupts must be disabled.
 * @return index of free page sized chunk of disk space in
 *   the paging file, or -1 if the paging file is full
 */
int Find_Space_On_Paging_File(void) {
    // Disable_Interrupts();
    KASSERT(!Interrupts_Enabled());
    
    int index = 0, i;
    for(i = 0; i < BITMAP_SIZE; i++) {
        if (Free_BitMap[i]) {
            int l_index = __builtin_clzl(Free_BitMap[i]);
            Free_BitMap[i] ^= (1 << (31 - l_index));
            KASSERT0(l_index != (int)__builtin_clzl(Free_BitMap[i]), "hello");
            Print("pagefile index given = %x", (uint_t) (index+l_index));
            return index + l_index;
        }
        else {
            index += CHAR_BIT * sizeof(ulong_t);
        }
    }
    // Enable_Interrupts();
    return -1;
    // TODO_P(PROJECT_VIRTUAL_MEMORY_B, "Find free page in paging file");
    // return EUNSUPPORTED;
}

/**
 * Free a page-sized chunk of disk space in the paging file.
 * Interrupts must be disabled.
 * @param pagefileIndex index of the chunk of disk space
 */
void Free_Space_On_Paging_File(int pagefileIndex) {
    KASSERT(!Interrupts_Enabled());
    
    // Check if the index is within bounds
    KASSERT(pagefileIndex >= 0 && pagefileIndex < PAGE_FILE_SIZE);

    int index1 = pagefileIndex >> 5, index2 = pagefileIndex & 0x1F;
    Free_BitMap[index1] |= (1 << (31 - index2));


    // TODO_P(PROJECT_VIRTUAL_MEMORY_B, "Free page in paging file");
}

/**
 * Write the contents of given page to the indicated block
 * of space in the paging file.
 * @param paddr a pointer to the physical memory of the page
 * @param vaddr virtual address where page is mapped in user memory
 * @param pagefileIndex the index of the page sized chunk of space
 *   in the paging file
 */
void Write_To_Paging_File(void *paddr, ulong_t vaddr, int pagefileIndex) {
    struct Page *page = Get_Page((ulong_t) paddr);
    page->flags &= ~(PAGE_PAGEABLE); 
    page->flags |= PAGE_LOCKED;
    KASSERT(!(page->flags & PAGE_PAGEABLE));    /* Page must be locked! */
    
    // int i;
    // for(i = 0; i < 8; i++) {
    //     Block_Write(pdev, 8 * pagefileIndex + i, (void*)page + 512 * i);
    // }


    // struct Page *page = Get_Page((ulong_t) paddr);
    // KASSERT(!(page->flags & PAGE_PAGEABLE));    /* Page must be locked! */
    // struct disk_page *disk_page1 = &s_diskPageList[pagefileIndex];
    // disk_page1->crc = crc32(0,paddr,PAGE_SIZE);
    // disk_page1->vaddr = vaddr;
    ulong_t i;
    //Write the data of the page
    for (i = 0; i < SECTORS_PER_PAGE; ++i) {
    ulong_t blockNum = (pagefileIndex * SECTORS_PER_PAGE) + Get_Paging_Device()->startSector + i;
    int dirty = Block_Write(Get_Paging_Device()->dev, blockNum, ((void*) paddr) + i*SECTOR_SIZE);
    if (dirty < 0)
       Print("Unable to blockwrite");
   }



    
 //    extern struct Page *g_pageList;
 //    ulong_t index = page - g_pageList;
 //    PF_Map[index] = pagefileIndex;

    page->flags = 0;    
    // page->flags |= PAGE_ALLOCATED;
    page->flags |= PAGE_PAGEABLE;
    page->flags &= ~(PAGE_LOCKED);

    page->entry->present = 0;
	page->entry->kernelInfo = KINFO_PAGE_ON_DISK;
    page->entry->pageBaseAddr = pagefileIndex;

    // TODO_P(PROJECT_VIRTUAL_MEMORY_B, "Write page data to paging file");
}

/**
 * Read the contents of the indicated block
 * of space in the paging file into the given page.
 * @param paddr a pointer to the physical memory of the page
 * @param vaddr virtual address where page will be re-mapped in
 *   user memory
 * @param pagefileIndex the index of the page sized chunk of space
 *   in the paging file
 */
void Read_From_Paging_File(void *paddr, ulong_t vaddr, int pagefileIndex) {
    
	struct Page *page = Get_Page((ulong_t) paddr);
    page->flags &= ~(PAGE_PAGEABLE);
    page->flags |= PAGE_LOCKED;
	KASSERT(!(page->flags & PAGE_PAGEABLE));    /* Page must be locked! */


    // int i;
    // for(i = 0; i < 8; i++) {
    //     Print("checking...\n");
    // check();
    //     Block_Read(pdev, 8 * pagefileIndex + i, (void*)page + 512 * i);
    // }


    //     struct Page *page = Get_Page((ulong_t) paddr);
    // KASSERT(!(page->flags & PAGE_PAGEABLE));     Page must be locked! 
    // struct disk_page *disk_page1 = &s_diskPageList[pagefileIndex];
    ulong_t i;
    //Read the data of the page
    for (i = 0; i < SECTORS_PER_PAGE; ++i) {
    ulong_t blockNum = (pagefileIndex * SECTORS_PER_PAGE) + Get_Paging_Device()->startSector + i;
    int dirty = Block_Read(Get_Paging_Device()->dev, blockNum, ((void*) paddr) + i*SECTOR_SIZE);
    if (dirty < 0)
        Print("Unable to block read");
    }
            // while(1){Print("yahi chutiya hai\n");} 

    page->flags = 0;    
    page->flags |= PAGE_ALLOCATED;
    page->flags |= PAGE_PAGEABLE;
    page->flags &= ~(PAGE_LOCKED);

    page->entry->present = 1;
    page->entry->kernelInfo = KINFO_PAGE_ON_DISK;
    page->entry->pageBaseAddr = ((ulong_t) paddr) >> 12;

	

    //TODO_P(PROJECT_VIRTUAL_MEMORY_B, "Read page data from paging file");
}


void *Mmap_Impl(void *ptr, unsigned int length, int prot, int flags, int fd) {
    TODO_P(PROJECT_MMAP, "Mmap setup mapping");
    return NULL;
}

bool Is_Mmaped_Page(struct User_Context * context, ulong_t vaddr) {
    // TODO_P(PROJECT_MMAP, "is this passed vaddr an mmap'd page in the passed user context");
    //Print("Looking for %lu\n", vaddr);
    return false;
}

void Write_Out_Mmaped_Page(struct User_Context *context, ulong_t vaddr) {
    TODO_P(PROJECT_MMAP, "Mmap write back dirty mmap'd page");
}

int Munmap_Impl(ulong_t ptr) {
    TODO_P(PROJECT_MMAP, "unmapp the pages");
}

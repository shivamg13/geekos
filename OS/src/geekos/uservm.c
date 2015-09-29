/*
 * Paging-based user mode implementation
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
 * $Revision: 1.51 $
 */

#include <geekos/int.h>
#include <geekos/mem.h>
#include <geekos/paging.h>
#include <geekos/malloc.h>
#include <geekos/string.h>
#include <geekos/argblock.h>
#include <geekos/kthread.h>
#include <geekos/range.h>
#include <geekos/vfs.h>
#include <geekos/user.h>
#include <geekos/projects.h>
#include <geekos/gdt.h>
#include <geekos/uservm.h>

#define DEFAULT_USER_STACK_SIZE 8192 

 extern Spin_Lock_t kthreadLock;
extern uint_t g_freePageCount;

 int userDebug = 0;
#define Debug(args...) if (userDebug) Print("uservm: " args)


/* ----------------------------------------------------------------------
 * Private functions
 * ---------------------------------------------------------------------- */

// TODO: Add private functions
int gfp_old, gfp_new;
uint_t g_freePagecount = 30690;
 static struct User_Context *Create_User_Context(ulong_t size) {
    struct User_Context *context;
    int index;
    uint_t i,j;
    
    ulong_t kernel_pages;
    ulong_t kernel_PDEntries;
    ulong_t context_size;
    ulong_t context_pages;
    /* Size must be a multiple of the page size */
    size = Round_Up_To_Page(size);
    kernel_pages = KERNEL_SPACE_END>>12;
    kernel_PDEntries = kernel_pages/NUM_PAGE_TABLE_ENTRIES;
    if (userDebug)
        Print("Size of user memory == %lu (%lx) (%lu pages)\n", size, size,
          size / PAGE_SIZE);
    
    pde_t * UserPageDir;
    
    UserPageDir = (pde_t*) Alloc_Page();
    
    
    for(i=0; i<kernel_PDEntries; i++) {
        pde_t entry = {0};
        UserPageDir[i] = PageDir[i];
    }
    
    for(i=kernel_PDEntries;i<NUM_PAGE_DIR_ENTRIES;i++){
        /* present bit is set to 0 */
        pde_t entry = {0};
        entry.flags = VM_USER | VM_WRITE;
        UserPageDir[i] = entry;
    }
    
    //Map APIC and IO APIC
    UserPageDir[1019] = PageDir[1019];
    
    /* Allocate memory for the user context */
    Disable_Interrupts();
    // context_size=Round_Up_To_Page(sizeof(*context));
    // context_pages = context_size/PAGE_SIZE;
    // context=(kernel_PDEntries<<22)| (1<<12);
    // for(i=0; i<(context_pages/NUM_PAGE_TABLE_ENTRIES) + (context_pages%NUM_PAGE_TABLE_ENTRIES!=0?1:0); i++) {
    
    //     pde_t entry = {0};
    //         pte_t *pageTable;
    
    //     /* Allocate a page table and clear it */
    //         pageTable = Alloc_Page();
    //         memset(pageTable, '\0', 4096);
    
    //     /* Create a page directory entry pointing to this page table */
    //         entry.present = 1;
    //         entry.pageTableBaseAddr = ((ulong_t) pageTable) >> 12;
    //         entry.flags = VM_WRITE;
    
    //         UserPageDir[kernel_PDEntries+i] = entry;
    
    //     for(j=0; j<(context_pages<NUM_PAGE_TABLE_ENTRIES? context_pages: NUM_PAGE_TABLE_ENTRIES); j++)
    //     {
    //         if(i==0 && j==0)
    //         {
    //             pte_t entry={0};
    //             pageTable[j]=entry;
    //             continue;
    //         }
    
    
    
    //     }
    //     context_pages -= NUM_PAGE_TABLE_ENTRIES;
    //     if(i==0) context_pages++;
    // }
    
    //See where exactly context should reside
    context = (struct User_Context *)Malloc(sizeof(*context));
    if (context != 0) {
        memset(context, 0, sizeof(struct User_Context));
        context->memory=(char*)(USER_VM_START);
        //context->memory = Malloc(size);
    }
    Enable_Interrupts();
    
    if (context == 0 || context->memory == 0)
        goto fail;
    
    /*
     * Fill user memory with zeroes;
     * leaving it uninitialized is a potential security flaw
     */
    //memset(context->memory, '\0', size);
     context->pageDir=UserPageDir;
     context->size = size;

    /* Allocate an LDT descriptor for the user context */
     context->ldtDescriptor = Allocate_Segment_Descriptor();
     if (context->ldtDescriptor == 0)
        goto fail;
    if (userDebug)
        Print("Allocated descriptor %d for LDT\n",
          Get_Descriptor_Index(context->ldtDescriptor));
    Init_LDT_Descriptor(context->ldtDescriptor, context->ldt,
        NUM_USER_LDT_ENTRIES);
    index = Get_Descriptor_Index(context->ldtDescriptor);
    context->ldtSelector = Selector(KERNEL_PRIVILEGE, true, index);
    
    /* Initialize code and data segments within the LDT */
    Init_Code_Segment_Descriptor(&context->ldt[0],
       (ulong_t) context->memory,
       size / PAGE_SIZE, USER_PRIVILEGE);
    Init_Data_Segment_Descriptor(&context->ldt[1],
       (ulong_t) context->memory,
       size / PAGE_SIZE, USER_PRIVILEGE);
    context->csSelector = Selector(USER_PRIVILEGE, false, 0);
    context->dsSelector = Selector(USER_PRIVILEGE, false, 1);
    
    /* Nobody is using this user context yet */
    context->refCount = 0;
    
    //context->csSelector = USER_CS;
    //context->dsSelector = USER_DS;
    
    /* Success! */
    return context;
    
    fail:
    /* We failed; release any allocated memory */
    Disable_Interrupts();
    if (context != 0) {
        if (context->memory != 0)
            Free(context->memory);
        Free(context);
    }
    Enable_Interrupts();
    
    return 0;
}



/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

 bool Free_Pages_User_Process(pde_t * page_dir)
 {
    pde_t * pdir; int i;

    g_freePagecount -= (gfp_old/4096);
    g_freePageCount = MIN_FREE_PAGES>g_freePagecount?MIN_FREE_PAGES:g_freePagecount; 
    bool flag;
    flag=Begin_Int_Atomic();
    // for(i = 0; g_freePageCount < MIN_FREE_PAGES && i < gfp_old/4096; i++)
    //     Print("FFM running!\n");
    if(page_dir==NULL)
    {
        return true;
    }

    for(pdir=page_dir+NUM_PAGE_DIR_ENTRIES/2; pdir < page_dir+NUM_PAGE_DIR_ENTRIES; pdir++)
    {
        pte_t * ptable;
        pte_t * ptable_first;

        if(!pdir->present)
        {
            continue;
        }
        ptable_first=(pte_t*) (pdir->pageTableBaseAddr << 12);
        for(ptable=ptable_first; ptable<ptable_first+NUM_PAGE_TABLE_ENTRIES; ptable++)
        {
            if(ptable->pageBaseAddr >= (int)0xfec00) {
                goto skip;
            }

            if(ptable->present)
            {
                Free_Page( (void*) (ptable->pageBaseAddr << 12));
            }
            else if(ptable->kernelInfo==KINFO_PAGE_ON_DISK)
            {
                Free_Space_On_Paging_File(ptable->pageBaseAddr);                
            }
        }
        
        Free_Page(ptable_first);

    }
    skip:
    Free_Page(page_dir); 

    End_Int_Atomic(flag);

    return true;
}


/*
 * Destroy a User_Context object, including all memory
 * and other resources allocated within it.
 */
 void Destroy_User_Context(struct User_Context *context) {
    /*
     * Hints:
     * - Free all pages, page tables, and page directory for
     *   the process (interrupts must be disabled while you do this,
     *   otherwise those pages could be stolen by other processes)
     * - Free semaphores, files, and other resources used
     *   by the process
     */
    // TODO_P(PROJECT_VIRTUAL_MEMORY_A,
    //   "Destroy User_Context data structure after process exits");
     gfp_new = g_freePageCount;
     if(context == NULL)
     {
        Print("Null Context error!\n");
        return;
    }
    
    Free_Segment_Descriptor(context->ldtDescriptor);
    //Set_PDBR(PageDir);
    if(context->pageDir!=NULL)
    {
        Free_Pages_User_Process(context->pageDir);
    }
    //context->pageDir = 0;
    bool iflag;
    iflag = Begin_Int_Atomic();    
    Free(context);
    End_Int_Atomic(iflag); 
    //Set_PDBR(PageDir);
    int i;
    //for(i=0; i<1000000000; i++);
        //Print("fcr4c");

    //for(i=0; i<1000000000; i++);
        //Print("fcr4c");
    // Print("Num free pages = %u\n", g_freePagecount);
}



int Alloc_Pages_User(pde_t *pageDir,uint_t startAddress,uint_t sizeInMemory) {
    uint_t pagedir_index=startAddress>>22;
    uint_t page_index=(startAddress<<10)>>22;
    // Print("Allocated %x\n", (unsigned int)startAddress);
    pde_t *pagedir_entry = pageDir+pagedir_index;
    pte_t *page_entry;
    
    ulong_t num_pages, num_pages_temp;
    void *page_addr;
    num_pages=Round_Up_To_Page(startAddress-Round_Down_To_Page(startAddress)+sizeInMemory)/PAGE_SIZE;
    
    while(num_pages>0) {
        if(pagedir_entry->present)
        {
            page_entry=(pte_t *)(pagedir_entry->pageTableBaseAddr<<12);
        }
        else
        {
            page_entry=(pte_t*) Alloc_Page();
            if(page_entry==NULL)
            {
                Print("can not allocate page in Alloc_Pages_User/n");
                return -1;
            }
            memset(page_entry,0,PAGE_SIZE);
            *((uint_t*)pagedir_entry)=0;
            pagedir_entry->present=1;
            pagedir_entry->flags=VM_WRITE | VM_READ | VM_USER;
            pagedir_entry->globalPage=0;
            pagedir_entry->pageTableBaseAddr=(ulong_t)page_entry >> 12;
        }

        page_entry+=page_index;
        
        uint_t i;
        uint_t first_page_addr=0;
        for(i=0;i<(num_pages<(NUM_PAGE_TABLE_ENTRIES - page_index)? num_pages : (NUM_PAGE_TABLE_ENTRIES - page_index));i++)
        {
            if(!page_entry->present)
            {
                page_addr=Alloc_Pageable_Page(page_entry, Round_Down_To_Page(startAddress));
                
                if(page_addr==NULL)
                {
                    Print("can not allocate page in Alloc_Pages_User/n");
                    return -1;
                }
                *((uint_t*)page_entry)=0;
                page_entry->present=1;
                page_entry->flags=VM_WRITE | VM_READ | VM_USER;
                page_entry->globalPage = 0;
                page_entry->pageBaseAddr = (ulong_t)page_addr>>12;


                KASSERT(page_addr!= 0);
                if(i==0)
                {
                    first_page_addr = (uint_t) page_addr;
                }
            }
            page_entry++;
            startAddress+=PAGE_SIZE;
        }
        num_pages -= ((num_pages<(NUM_PAGE_TABLE_ENTRIES - page_index)? num_pages : (NUM_PAGE_TABLE_ENTRIES - page_index)));
        pagedir_entry++;
        page_index = 0;
    }
    
    return 0;
    
}


int Alloc_Pages_User_Disk(pde_t *pageDir,uint_t startAddress,uint_t sizeInMemory) {
    uint_t pagedir_index=startAddress>>22;
    uint_t page_index=(startAddress<<10)>>22;
    // Print("Allocated %x\n", (unsigned int)startAddress);
    pde_t *pagedir_entry = pageDir+pagedir_index;
    pte_t *page_entry;
    
    ulong_t num_pages, num_pages_temp;
    int page_addr;
    num_pages=Round_Up_To_Page(startAddress-Round_Down_To_Page(startAddress)+sizeInMemory)/PAGE_SIZE;
    
    while(num_pages>0) {
        if(pagedir_entry->present)
        {
            page_entry=(pte_t *)(pagedir_entry->pageTableBaseAddr<<12);
        }
        else
        {
            page_entry=(pte_t*) Alloc_Page();
            if(page_entry==NULL)
            {
                Print("can not allocate page in Alloc_Pages_User/n");
                return -1;
            }
            memset(page_entry,0,PAGE_SIZE);
            *((uint_t*)pagedir_entry)=0;
            pagedir_entry->present=1;
            pagedir_entry->flags=VM_WRITE | VM_READ | VM_USER;
            pagedir_entry->globalPage=0;
            pagedir_entry->pageTableBaseAddr=(ulong_t)page_entry >> 12;
        }

        page_entry+=page_index;
        
        uint_t i;
        //uint_t first_page_addr=0;
        for(i=0;i<(num_pages<(NUM_PAGE_TABLE_ENTRIES - page_index)? num_pages : (NUM_PAGE_TABLE_ENTRIES - page_index));i++)
        {
            if(!page_entry->present && !(page_entry->kernelInfo&KINFO_PAGE_ON_DISK))
            {
                //page_addr=Alloc_Pageable_Page(page_entry, Round_Down_To_Page(startAddress));
                /*Disable_Interrupts();
                   page_addr=Find_Space_On_Paging_File(); 
                Enable_Interrupts();*/

                // if(page_addr==NULL)
                // {
                //     Print("can not allocate page in Alloc_Pages_User/n");
                //     return -1;
                // }
                   *((uint_t*)page_entry)=0;
                   page_entry->present=0;
                   page_entry->flags=VM_WRITE | VM_READ | VM_USER;
                   page_entry->globalPage = 0;
                ///page_entry->kernelInfo |= KINFO_PAGE_ON_DISK;
                //page_entry->pageBaseAddr = (ulong_t)page_addr;


               // KASSERT(page_addr!= 0);
                   if(i==0)
                   {
                    //first_page_addr = (uint_t) page_addr;
                   }
               }
               else if(page_entry->present)
               {
                Print("Page Entry should not be present\n");
                KASSERT(0);
            }
            page_entry++;
            startAddress+=PAGE_SIZE;
        }
        num_pages -= ((num_pages<(NUM_PAGE_TABLE_ENTRIES - page_index)? num_pages : (NUM_PAGE_TABLE_ENTRIES - page_index)));
        pagedir_entry++;
        page_index = 0;
    }
    
    return 0;
    
}


uint_t lin_to_phyaddr(pde_t * page_dir,uint_t lin_address)
{
    uint_t pagedir_index=lin_address>>22;
    uint_t page_index=(lin_address<<10)>>22;
    uint_t offset_address=lin_address & 0xfff;
    
    
    pde_t * pagedir_entry=page_dir+pagedir_index;
    pte_t * page_entry=0;
    
    if(pagedir_entry->present)
    {
        page_entry=(pte_t*) ((uint_t)pagedir_entry->pageTableBaseAddr << 12);
        page_entry+=page_index;
        //-----------------mydebug----------------------
        if(page_entry->present==0)
        {
            Print("the page is not present!\n");
            Print("Linear address is %x\n", lin_address);
            KASSERT(0);
        }
        //----------------------------------------------
        return (page_entry->pageBaseAddr << 12)+offset_address;
    }
    else
    {
        Print("Trying to resolve non-existent address%x\n", lin_address);
        return 0;
    }
}


uint_t lin_to_diskaddr(pde_t * page_dir,uint_t lin_address)
{
    uint_t pagedir_index=lin_address>>22;
    uint_t page_index=(lin_address<<10)>>22;
    uint_t offset_address=lin_address & 0xfff;
    
    
    pde_t * pagedir_entry=page_dir+pagedir_index;
    pte_t * page_entry=0;
    
    if(pagedir_entry->present)
    {
        page_entry=(pte_t*) ((uint_t)pagedir_entry->pageTableBaseAddr << 12);
        page_entry+=page_index;
        //-----------------mydebug----------------------
        //if(page_entry->present!=0 || !(page_entry->kernelInfo&KINFO_PAGE_ON_DISK))
        if(page_entry->present!=0)
        {

            Print("the page is not present in disk!\n");
            Print("Linear address is %x\n", lin_address);
            KASSERT(0);
        }

        //----------------------------------------------
        return (page_entry->pageBaseAddr<<12) + offset_address;
    }
    else
    {
        Print("Trying to resolve non-existent address%x\n", lin_address);
        return 0;
    }
}

pte_t* get_entry(pde_t * page_dir,uint_t lin_address)
{
   uint_t pagedir_index=lin_address>>22;
   uint_t page_index=(lin_address<<10)>>22;
   uint_t offset_address=lin_address & 0xfff;


   pde_t * pagedir_entry=page_dir+pagedir_index;
   pte_t * page_entry=0;

   if(pagedir_entry->present)
   {
    page_entry=(pte_t*) ((uint_t)pagedir_entry->pageTableBaseAddr << 12);
    page_entry+=page_index;
    return page_entry;
}
else
{
    Print("Trying to get entry for non-existent address%x\n", lin_address);
    return 0;
}   
}


bool Copy_Pages_User(pde_t * page_dir, uint_t dest_user, char * src, uint_t byte_num)
{
    uint_t phyMemStart;
    uint_t temp_length;
    int page_nums;
    struct Page * page;

    if(byte_num==0) {
        return true;
    }
    
    if(Round_Down_To_Page(dest_user+byte_num) == Round_Down_To_Page(dest_user))
    {
        temp_length=byte_num;
        page_nums=1;
    }
    else
    {
        temp_length=Round_Up_To_Page(dest_user)-dest_user;
        byte_num-=temp_length;
        page_nums=0;
    }
    phyMemStart=lin_to_phyaddr(page_dir, dest_user);
    if(phyMemStart==0)
    {
        Print("Error! Linear to physical memory transformation not possible.\n");
        return false;
    }
    page = Get_Page(phyMemStart);
    
    Disable_Interrupts();
    page->flags &= ~ PAGE_PAGEABLE;
    Enable_Interrupts();
    
    memcpy((char *)phyMemStart, src, temp_length);
    page->flags |= PAGE_PAGEABLE;
    
    if(page_nums == 1)
    {
        return true;
    }
    
    
    
    dest_user+=temp_length;
    src+=temp_length;
    
    
    while(dest_user!=Round_Down_To_Page(dest_user + byte_num))
    {

        phyMemStart=lin_to_phyaddr(page_dir,dest_user);
        if(phyMemStart == 0)
        {
            Print("Error! Linear to physical memory transformation not possible.\n");
            return false;
        }
        page = Get_Page(phyMemStart);
        
        Disable_Interrupts();
        page->flags &= ~ PAGE_PAGEABLE;
        Enable_Interrupts();
        
        memcpy((char*)phyMemStart, src, PAGE_SIZE);
        page->flags |= PAGE_PAGEABLE;
        
        dest_user+=PAGE_SIZE;
        byte_num-=PAGE_SIZE;
        src+=PAGE_SIZE;
    }
    
    //Spillover to final page
    if(byte_num!=0)
    {
        phyMemStart = lin_to_phyaddr(page_dir, dest_user);
        if(phyMemStart==0)
        {
            Print("Error! Linear to physical memory transformation not possible.\n");
            return false;
        }

        Disable_Interrupts();
        page->flags &= ~ PAGE_PAGEABLE;
        Enable_Interrupts();

        memcpy((char*)phyMemStart, src, byte_num);
        page->flags |= PAGE_PAGEABLE;
    //Print("user program loaded\n");
    }
    return true;
}


bool Copy_Pages_User_Disk(pde_t * page_dir, uint_t dest_user, char * src, uint_t byte_num)
{
    uint_t diskStart;
    uint_t temp_length;
    int page_nums;
    struct Page * page;

    if(byte_num==0) {
        Print("0 bytes to copy\n");
        return true;
    }
    
    if(Round_Down_To_Page(dest_user+byte_num) == Round_Down_To_Page(dest_user))
    {
        temp_length=byte_num;
        page_nums=1;
    }
    else
    {
        Print("Entered copy_pages_disk with byte_num=%i\n",byte_num);
        temp_length=Round_Up_To_Page(dest_user)-dest_user;
        byte_num-=temp_length;
        page_nums=0;
    }
    
    if(temp_length>0)
    {
        Disable_Interrupts(); 
        diskStart=Find_Space_On_Paging_File();
        Enable_Interrupts();

        Print("temp_length is  greater than 0\n");


        char* temppage=Alloc_Pageable_Page(get_entry(page_dir, dest_user),Round_Down_To_Page(dest_user));




        memcpy(temppage, src, temp_length);

        Write_To_Paging_File(temppage, Round_Down_To_Page(dest_user), diskStart);
    //Free_Page(temppage);

        if(page_nums == 1)
        {
            return true;
        }

        dest_user+=temp_length;
        src+=temp_length;

    }

    while(dest_user!=Round_Down_To_Page(dest_user + byte_num))
    {

        Print("while eneterd\n");

        Disable_Interrupts(); 
        diskStart=Find_Space_On_Paging_File();
        Enable_Interrupts();

        Print("temp_length is  greater than 0\n");


        char* temppage=Alloc_Pageable_Page(get_entry(page_dir, dest_user),Round_Down_To_Page(dest_user));




        memcpy(temppage, src, temp_length);

        Write_To_Paging_File(temppage, Round_Down_To_Page(dest_user), diskStart);
   // Print("Allocated2=%d\n",paget->flags & PAGE_ALLOCATED);
    //Free_Page(temppage);

 //Print("exited 22\n");

        // if(phyMemStart == 0)
        // {
        //     Print("Error! Linear to physical memory transformation not possible.\n");
        //     return false;
        // }
        // page = Get_Page(phyMemStart);
        
        // Disable_Interrupts();
        // page->flags &= ~ PAGE_PAGEABLE;
        // Enable_Interrupts();
        
        // memcpy((char*)phyMemStart, src, PAGE_SIZE);
        // page->flags |= PAGE_PAGEABLE;
        
        dest_user+=PAGE_SIZE;
        byte_num-=PAGE_SIZE;
        src+=PAGE_SIZE;
    }
    
 //Print("exited 2\n");

    //Spillover to final page
    if(byte_num!=0)
    {
        Disable_Interrupts(); 
        diskStart=Find_Space_On_Paging_File();
        Enable_Interrupts();

        Print("temp_length is  greater than 0\n");


        char* temppage=Alloc_Pageable_Page(get_entry(page_dir, dest_user),Round_Down_To_Page(dest_user));




        memcpy(temppage, src, temp_length);

        Write_To_Paging_File(temppage, Round_Down_To_Page(dest_user), diskStart);
    //Free_Page(temppage);
    // memcpy((char*)phyMemStart, src, byte_num);
    // page->flags |= PAGE_PAGEABLE;
    // Print("user program loaded\n");
    }
 //Print("exited final\n");
    return true;

}

/*
 * Load a user executable into memory by creating a User_Context
 * data structure.
 * Params:
 * exeFileData - a buffer containing the executable to load
 * exeFileLength - number of bytes in exeFileData
 * exeFormat - parsed ELF segment information describing how to
 *   load the executable's text and data segments, and the
 *   code entry point address
 * command - string containing the complete command to be executed:
 *   this should be used to create the argument block for the
 *   process
 * pUserContext - reference to the pointer where the User_Context
 *   should be stored
 *
 * Returns:
 *   0 if successful, or an error code (< 0) if unsuccessful
 */
 bool initflag=true;
 int Load_User_Program(char *exeFileData, ulong_t exeFileLength,
  struct Exe_Format *exeFormat, const char *command,
  struct User_Context **pUserContext) {
    /*
     * Hints:
     * - This will be similar to the same function in userseg.c
     * - Determine space requirements for code, data, argument block,
     *   and stack
     * - Allocate pages for above, map them into user address
     *   space (allocating page directory and page tables as needed)
     * - Fill in initial stack pointer, argument block address,
     *   and code entry point fields in User_Context
     */
     Print("Loading user program\n");
     int i,res;
     ulong_t maxva = 0;
     unsigned numArgs;

     ulong_t size, argBlockAddr, argBlockSize;
     void *paddr = 0;
     struct User_Context *userContext = 0;
     pde_t* pageDirectory;
     uint_t stack_addr, arg_addr;
    /* Find maximum virtual address */
     for (i = 0; i < exeFormat->numSegments; ++i) {
        struct Exe_Segment *segment = &exeFormat->segmentList[i];
        ulong_t topva = segment->startAddress + segment->sizeInMemory;  /* FIXME: range check */
        Print("Segment start address is %lu\n and size is %lu\n",segment->startAddress,segment->sizeInMemory);
        if (topva > maxva)
            maxva = topva;
    }
    
    /* Determine size required for argument block */
    Get_Argument_Block_Size(command, &numArgs, &argBlockSize);
    
    
    /*
     * Now we can determine the size of the memory block needed
     * to run the process.
     */
     size = Round_Up_To_Page(maxva) + DEFAULT_USER_STACK_SIZE;
     argBlockAddr = size;
     size += argBlockSize;
     gfp_old = size;

     if(size>USER_VM_SIZE) {
        Print("Falling short of physical memory :(");
            return -1;
        }

    /* Create User_Context */
        userContext = Create_User_Context(size);
        if (userContext == 0)
            return -1;
        pageDirectory=userContext->pageDir;
    // Disable_Interrupts();

        for(i=0; i<exeFormat->numSegments; i++)
        {


            res=Alloc_Pages_User(pageDirectory,exeFormat->segmentList[i].startAddress+USER_VM_START,exeFormat->segmentList[i].sizeInMemory);
            if(res!=0)
            {
                Print("Page cant be allocated for copying the segment\n");
                return -1;
            }

            res=Copy_Pages_User(pageDirectory,exeFormat->segmentList[i].startAddress+USER_VM_START,exeFileData+exeFormat->segmentList[i].offsetInFile,exeFormat->segmentList[i].lengthInFile);
            if(res!=true)
            {
                Print("Segment Copy Failed\n");
                return -1;
            }


        }


        if(argBlockSize > PAGE_SIZE)
        {
            Print("Argument Block is too big/n");
            return -1;
        }

        ulong_t USER_VM_LEN = Round_Up_To_Page(size);
        arg_addr=Round_Down_To_Page(USER_VM_LEN-argBlockSize);
        Disable_Interrupts();
        char* block_buf=Malloc(argBlockSize);
        Enable_Interrupts();
        KASSERT(block_buf!=NULL);
        Format_Argument_Block(block_buf,numArgs,arg_addr,command);

        if(initflag==false)
    {//Load argument block in swap space

        uint_t startAddress=arg_addr+USER_VM_START;
        uint_t pagedir_index=startAddress>>22;
        uint_t page_index=(startAddress<<10)>>22;
    // Print("Allocated %x\n", (unsigned int)startAddress);
        pde_t *pagedir_entry = pageDirectory+pagedir_index;
        pte_t *page_entry;

    //ulong_t num_pages, num_pages_temp;
        int page_addr;
    //num_pages=Round_Up_To_Page(startAddress-Round_Down_To_Page(startAddress)+sizeInMemory)/PAGE_SIZE;


        if(pagedir_entry->present)
        {
            page_entry=(pte_t *)(pagedir_entry->pageTableBaseAddr<<12);
        }
        else
        {
            page_entry=(pte_t*) Alloc_Page();
            if(page_entry==NULL)
            {
                Print("can not allocate page in Alloc_Pages_User/n");
                return -1;
            }
            memset(page_entry,0,PAGE_SIZE);
            *((uint_t*)pagedir_entry)=0;
            pagedir_entry->present=1;
            pagedir_entry->flags=VM_WRITE | VM_READ | VM_USER;
            pagedir_entry->pageTableBaseAddr=(ulong_t)page_entry >> 12;


        }
        page_entry+=page_index;

        *((uint_t*)page_entry)=0;
        page_entry->present=0;
        page_entry->flags=VM_WRITE | VM_READ | VM_USER;
        page_entry->globalPage = 0;
        page_entry->kernelInfo = KINFO_PAGE_ON_DISK;
        Disable_Interrupts();
        page_entry->pageBaseAddr = (ulong_t)Find_Space_On_Paging_File();
        Enable_Interrupts();

        char* temppage=Alloc_Pageable_Page(page_entry,arg_addr+USER_VM_START);




        memcpy(temppage, block_buf, argBlockSize);

        Write_To_Paging_File(temppage, arg_addr+USER_VM_START, page_entry->pageBaseAddr);

        int pagefile_index = page_entry->pageBaseAddr;
        void * paddr=Alloc_Pageable_Page(page_entry,arg_addr+USER_VM_START);
             page_entry->present=1;
        //do we need to set these flags ????
        page_entry->kernelInfo &= ~(KINFO_PAGE_ON_DISK);
        page_entry->flags=VM_WRITE | VM_READ | VM_USER;
        page_entry->globalPage = 0;
        page_entry->pageBaseAddr = (ulong_t)paddr>>12;
        //Enable_Interrupts();
        struct Page * stemp = Get_Page((ulong_t)paddr);
        stemp->flags &= ~(PAGE_PAGEABLE);
        stemp->flags |= PAGE_LOCKED;
        // Enable_Interrupts();

        Read_From_Paging_File(paddr,arg_addr+USER_VM_START, pagefile_index);
        // Disable_Interrupts();
        stemp->flags |= PAGE_PAGEABLE;
        stemp->flags &= ~(PAGE_LOCKED);
        
       // Copy_Pages_User(pageDirectory, arg_addr+USER_VM_START, block_buf,argBlockSize);
       // Disable_Interrupts();
        //Free_Space_On_Paging_File(pagefile_index);


    }
    else
    {//Load argument block in memory
       res=Alloc_Pages_User(pageDirectory, arg_addr+USER_VM_START, argBlockSize);
       if(res!=0)
       {
        return -1;
    }
    res=Copy_Pages_User(pageDirectory, arg_addr+USER_VM_START, block_buf,argBlockSize);
    if(res!=true)
    {
        return -1;
    }  

}
Disable_Interrupts();
Free(block_buf);
Enable_Interrupts();

stack_addr=USER_VM_LEN-Round_Up_To_Page(argBlockSize)-DEFAULT_USER_STACK_SIZE;
if(initflag==false)
{
    res=Alloc_Pages_User_Disk(pageDirectory,stack_addr+USER_VM_START,DEFAULT_USER_STACK_SIZE);

    if(res!=0)
    {
        return -1;
    }
}
else
{
   res=Alloc_Pages_User(pageDirectory,stack_addr+USER_VM_START,DEFAULT_USER_STACK_SIZE);

   if(res!=0)
   {
    return -1;
    }   
}
	userContext->argBlockAddr = arg_addr;
	userContext->stackPointerAddr = arg_addr;
	userContext->entryAddr = exeFormat->entryAddr;
	userContext->size = USER_VM_LEN;

	*pUserContext = userContext;
    // Print("Finished Loading\n");
    // int tempppt;
    // for(tempppt=0;tempppt<1000000000;tempppt++);
    // Enable_Interrupts();
	initflag=false;
	Check_Flags(pageDirectory, paddr, size);
	return 0;
}

/*
 * Copy data from user buffer into kernel buffer.
 * Returns true if successful, false otherwise.
 */
 bool Copy_From_User(void *destInKernel, ulong_t srcInUser, ulong_t numBytes) {
    /*
     * Hints:
     * - Make sure that user page is part of a valid region
     *   of memory
     * - Remember that you need to add 0x80000000 to user addresses
     *   to convert them to kernel addresses, because of how the
     *   user code and data segments are defined
     * - User pages may need to be paged in from disk before being accessed.
     * - Before you touch (read or write) any data in a user
     *   page, **disable the PAGE_PAGEABLE bit**.
     *
     * Be very careful with race conditions in reading a page from disk.
     * Kernel code must always assume that if the struct Page for
     * a page of memory has the PAGE_PAGEABLE bit set,
     * IT CAN BE STOLEN AT ANY TIME.  The only exception is if
     * interrupts are disabled; because no other process can run,
     * the page is guaranteed not to be stolen.
     */
     void* user_address=(void*)(USER_VM_START)+srcInUser;
     struct User_Context* userContext=CURRENT_THREAD->userContext;


     if((srcInUser+numBytes) < userContext->size)
     {
        memcpy(destInKernel, user_address, numBytes);
        return true;
    }
    return false;
    
    //TODO_P(PROJECT_VIRTUAL_MEMORY_A, "Copy user data to kernel buffer");
}

/*
 * Copy data from kernel buffer into user buffer.
 * Returns true if successful, false otherwise.
 */
 bool Copy_To_User(ulong_t destInUser, void *srcInKernel, ulong_t numBytes) {
    /*
     * Hints:
     * - Same as for Copy_From_User()
     * - Also, make sure the memory is mapped into the user
     *   address space with write permission enabled
     */

     void* user_address = (void*)(USER_VM_START) + destInUser;
     struct User_Context* userContext=CURRENT_THREAD->userContext;
     if((destInUser+numBytes) < userContext->size)
     {
        memcpy(user_address, srcInKernel ,numBytes);
        return true;
    }
    return false;
    //TODO_P(PROJECT_VIRTUAL_MEMORY_A, "Copy kernel data to user buffer");
}

/*
 * Copy data from user buffer into user buffer.
 * Returns true if successful, false otherwise.
 */
 bool Copy_User_To_User(void *destInUser, ulong_t srcInUser, ulong_t numBytes) {
    /*
     * Hints:
     * - Make sure that each user page is part of a valid region
     *   of memory
     * - Remember that you need to add 0x80000000 to user addresses
     *   to convert them to kernel addresses, because of how the
     *   user code and data segments are defined
     * - User pages may need to be paged in from disk before being accessed.
     * - Before you touch (read or write) any data in a user
     *   page, **disable the PAGE_PAGEABLE bit**.
     *
     * Be very careful with race conditions in reading a page from disk.
     * Kernel code must always assume that if the struct Page for
     * a page of memory has the PAGE_PAGEABLE bit set,
     * IT CAN BE STOLEN AT ANY TIME.  The only exception is if
     * the vmSpingLock is held; because no other process can run,
     * the page is guaranteed not to be stolen.
     */
     TODO_P(PROJECT_VIRTUAL_MEMORY_A, "Copy user data to kernel buffer");
     return true;
 }

// extern int Load_LDTR(ushort_t);  //--tobedone--

/*
 * Switch to user address space.
 */
 void Switch_To_Address_Space(struct User_Context *userContext) {
    /*
     * - If you are still using an LDT to define your user code and data
     *   segments, switch to the process's LDT
     * -
     */
     if(userContext == 0)
     {
        Print("Null User Context/n");
        return;
    }
    Set_PDBR((void*)userContext->pageDir);
    ushort_t ldtSelector;
    ldtSelector = userContext->ldtSelector;
    __asm__ __volatile__("lldt %0"::"a"(ldtSelector)
        );
    // Load_LDTR(userContext->ldtSelector); //--tobedone--
}






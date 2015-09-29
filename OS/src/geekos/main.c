/*
 * GeekOS C code entry point
 * Copyright (c) 2001,2003,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * Copyright (c) 2004, Iulian Neamtiu <neamtiu@cs.umd.edu>
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
 * $Revision: 1.53 $
 *
 */

#include <geekos/bootinfo.h>
#include <geekos/string.h>
#include <geekos/screen.h>
#include <geekos/mem.h>
#include <geekos/crc32.h>
#include <geekos/tss.h>
#include <geekos/int.h>
#include <geekos/kthread.h>
#include <geekos/trap.h>
#include <geekos/timer.h>
#include <geekos/keyboard.h>
#include <geekos/dma.h>
#include <geekos/ide.h>
#include <geekos/floppy.h>
#include <geekos/pfat.h>
#include <geekos/vfs.h>
#include <geekos/user.h>
#include <geekos/paging.h>
#include <geekos/gosfs.h>
#include <geekos/gfs2.h>
#include <geekos/cfs.h>
#include <geekos/net/ne2000.h>
#include <geekos/net/net.h>
#include <geekos/net/netbuf.h>
#include <geekos/net/arp.h>
#include <geekos/alarm.h>
#include <geekos/net/ip.h>
#include <geekos/net/routing.h>
#include <geekos/net/socket.h>
#include <geekos/net/rip.h>
#include <geekos/projects.h>
#include <geekos/sound.h>
#include <geekos/smp.h>
#include <geekos/io.h>

/*
 * Define this for a self-contained boot floppy
 * with a PFAT filesystem.  (Target "fd_aug.img" in
 * the makefile.)
 */
/*#define FD_BOOT*/

#ifdef FD_BOOT
#  define ROOT_DEVICE "fd0"
#  define ROOT_PREFIX "a"
#else
#  define ROOT_DEVICE "ide0"
#  define ROOT_PREFIX "c"
#endif

#define INIT_PROGRAM "/" ROOT_PREFIX "/shell.exe"



static void Mount_Root_Filesystem(void);
static void Spawn_Init_Process(void);

/*
 * Kernel C code entry point.
 * Initializes kernel subsystems, mounts filesystems,
 * and spawns init process.
 */

 extern void checkPaging(void);


 void Hardware_Shutdown() {

    // works with > 1.3 qemu with the command line: -device isa-debug-exit,iobase=0x501
    Out_Byte(0x501, 0x00);

    // works on Bochs, and QEMU prior to 1.4
    Out_Byte(0x8900, 'S');
    Out_Byte(0x8900, 'h');
    Out_Byte(0x8900, 'u');
    Out_Byte(0x8900, 't');
    Out_Byte(0x8900, 'd');
    Out_Byte(0x8900, 'o');
    Out_Byte(0x8900, 'w');
    Out_Byte(0x8900, 'n');
}

void Main(struct Boot_Info *bootInfo) {
    Init_BSS();
    Init_Screen();
    Init_Mem(bootInfo);
    

    Init_CRC32();
    Init_TSS();

    lockKernel();
    Init_Interrupts(0);
    Init_VM(bootInfo);
    
    Init_SMP();
    TODO_P(PROJECT_VIRTUAL_MEMORY_A,
     "initialize virtual memory page tables.");
    Init_Scheduler(0, (void *)KERN_STACK);
    Init_Traps();
    Init_Local_APIC(0);
    Init_Timer();

    Init_Keyboard();
    Init_DMA();
    /* Init_Floppy(); *//* floppy initialization hangs on virtualbox */
    Init_IDE();
    Init_PFAT();
    Init_GFS2();
    Init_GOSFS();
    Init_CFS();
    Init_Alarm();
    // Init_Pagefile();

    Release_SMP();

    /* Initialize Networking */
    Init_Network_Devices();
    Init_ARP_Protocol();
    Init_IP();
    Init_Routing();
    Init_Sockets();
    Init_RIP();
    /* End networking subsystem init */

    /* Initialize Sound */
    Init_Sound_Devices();
    /* End sound init */
    Mount_Root_Filesystem();

    Init_Pagefile();
    
    // TODO_P(PROJECT_VIRTUAL_MEMORY_A, "initialize page file.");

    Set_Current_Attr(ATTRIB(BLACK, GREEN | BRIGHT));
    Print("Welcome to GeekOS!\n");
    Set_Current_Attr(ATTRIB(BLACK, GRAY));

    TODO_P(PROJECT_SOUND, "play startup sound");

    Spawn_Init_Process();

    /* it's time to shutdown the system */
    Hardware_Shutdown();

    /* we should not get here */
}



static void Mount_Root_Filesystem(void) {
    if (Mount(ROOT_DEVICE, ROOT_PREFIX, "pfat") != 0)
        Print("Failed to mount /" ROOT_PREFIX " filesystem\n");
    else
        Print("Mounted /" ROOT_PREFIX " filesystem!\n");

}






static void Spawn_Init_Process(void) {
    int rc;
    struct Kernel_Thread *initProcess;

    /* Load and run a.exe, the "init" process */
    Print("Spawning init process (%s)\n", INIT_PROGRAM);
    rc = Spawn_Foreground(INIT_PROGRAM, INIT_PROGRAM, &initProcess);
    extern uint_t g_freePageCount;
	Print("Num free pages after shell spawned = %i\n", g_freePageCount);
    
    if (rc != 0) {
        Print("Failed to spawn init process: error code = %d\n", rc);
    } else {
        /* Wait for it to exit */
        int exitCode = Join(initProcess);
        Print("Init process exited with code %d\n", exitCode);
    }
}

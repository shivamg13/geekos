#include <geekos/bget.h>
#include <conio.h>
#include <stddef.h>
#include <geekos/kassert.h>

#include <geekos/screen.h>
#include <geekos/malloc.h>
#include <geekos/lock.h>
#include <string.h>


void *Malloc(ulong_t size) {
    bool iflag;
    void *result;



    result = bget(size);


    if (result)
        memset(result, '\0', size);

    if (!result) {
        // Print("Kernel Malloc pool exhaused, shutting down\n");
        
    	sbrk(size);

    	result = bget(size);


   	 	if (result)
        memset(result, '\0', size);

    	if (!result) {

        	//		Hardware_Shutdown();
    	}
	}
    return result;
}

void Free(void *buf) {
    bool iflag;

    

    brel(buf);

}

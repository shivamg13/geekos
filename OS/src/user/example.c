#include <conio.h>
#include<string.h>
#include<malloc.h>
#include<fileio.h>
#include <sched.h>

int main() 
{
	TotalCount();
TotalCount();
    char x[80];
    Read_Line2(x,80);
    Print("\n%s\n",x);
TotalCount();
     Open("lab",0);
	OpenCount();

	int xx = 2;
	Get_NewTOD(&xx);
	Print("TOD using Get_NewTOD: %d\n", xx);
	int y = Get_Time_Of_Day();
	Print("TOD using Get_Time_Of_Day: %d\n", y);
	TotalCount();
    return 0;
}

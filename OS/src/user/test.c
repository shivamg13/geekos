#include <sched.h>
#include <conio.h>
int main() {
	int x = 2;
	Get_NewTOD(&x);
	Print("%d\n", x);
	int y = Get_Time_Of_Day();
	Print("%d\n", y);
	return 0;
}
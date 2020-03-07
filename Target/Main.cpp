#include <iostream>

#include <Windows.h>


void injectTatget(char * str ,int  num )
{
	num = num*num*num + num;
	num = rand() + num;
	num = num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num*num;

	printf("Are you inject me : %s %d ?\n", str, num);
}



int main() {

	void(*ptrfunc)(char * str, int  num);
	ptrfunc = injectTatget;
	while (1)
	{
		std::cout << "main::while(1)" << std::endl;
		ptrfunc((char *)"I,m you father", rand());
		
		Sleep(1000);
	}
	return 0;
}

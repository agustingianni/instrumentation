/*
 * test_vtables.cpp
 *
 *  Created on: Mar 9, 2012
 *      Author: agustin
 */

#include <iostream>

using namespace std;

void *my_malloc(size_t size)
{
	cout << "my_malloc(" << size << ");\n";
	return (void *) (0xcafe0000 + size);
}

void my_free(void *ptr)
{
	cout << "my_free(" << ptr << ");\n";
}

int main(int argc, char **argv)
{
	void *ptr1 = my_malloc(0x1000);
	void *ptr2 = my_malloc(0x2000);
	void *ptr3 = my_malloc(0x3000);

	my_free(ptr1);
	my_free(ptr2);
	my_free(ptr3);

	return 0;
}


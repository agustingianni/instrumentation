/*
 * test1.cpp
 *
 *  Created on: Feb 11, 2012
 *      Author: agustin
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef WIN32
#include <unistd.h>
#endif

struct struct_a
{
	int field1;
	int field2;
	int field3;
	int field4;
};

int func_1(void)
{
	const char *filename = "/dev/zero";

	struct struct_a a;
	a.field1 = 0x130;
	a.field2 = 0x230;
	a.field3 = 0x330;
	a.field4 = 0x430;

	int fd = open(filename, O_RDONLY);
	if(fd < 0)
		return -1;

	if(read(fd, (void *) &a, sizeof(a)) != sizeof(a))
	{
		close(fd);
		return -1;
	}

	close(fd);

	return a.field1;
}

int main(int argc, char **argv)
{
	struct struct_a a;
	a.field1 = 0x100;
	a.field2 = 0x200;
	a.field3 = 0x300;
	a.field4 = 0x400;

	return func_1() + a.field1;
}


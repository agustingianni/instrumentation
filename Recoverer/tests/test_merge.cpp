#include <iostream>
using namespace std;

class ClassA
{
public:
	void method1()
	{
		field1 = 0x01010101;
	}

	void method2()
	{
		field2 = 0x02020202;
	}

	void method3()
	{
		field3 = 0x03030303;
	}

	int method4()
	{
		*(char *) &field1 = 0xca;
		*(char *) &field2 = 0xca;
		*(char *) &field3 = 0xca;

		return field1 + field2 + field3;
	}


private:
	int field1;
	int field2;
	int field3;
};

int main(int argc, char **argv)
{
	ClassA *obj = new ClassA();
	obj->method1();
	obj->method4();
	delete obj;

	obj = new ClassA();
	obj->method2();
	obj->method4();
	delete obj;

	obj = new ClassA();
	obj->method3();
	obj->method4();
	delete obj;

	return 0;
}

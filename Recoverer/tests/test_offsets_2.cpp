#include <iostream>

using namespace std;

class ClassA
{
public:
	ClassA()
	{
		field1 = 0;
		field2 = 0;
	}

	void method1()
	{
		*(((char *) &field1) + 0) = 0x11;
		*(((char *) &field1) + 1) = 0x22;
	}

private:
	int field1;
	int field2;
};

int main(int argc, char **argv)
{
	ClassA *obj = new ClassA();
	obj->method1();

	delete obj;

	return 0;
}

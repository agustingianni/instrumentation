#include <iostream>

using namespace std;

class ClassA
{
public:
	ClassA();
	void method1();
	void method2();
	void method3();
private:
	char c;
	int field1;
	int field2;
	int field3;
	short field4;
	short field5;
	int field6;
	int field7;
	double f;
};

ClassA::ClassA()
{
	f = 4000.5 * 1000.7;
}

void ClassA::method1()
{
	this->field1 = 0x1000;
	f = 0.1337 * this->field2;
	c = 0xcc;
}

void ClassA::method2()
{
	this->field2 = 0x2000;
}

void ClassA::method3()
{
	this->field5 = 0x1000;
	this->field7 = 0x1000;

}

int main(int argc, char **argv)
{
	ClassA *obj = new ClassA();
	obj->method1();
	obj->method2();
	obj->method3();

	delete obj;

	return 0;
}

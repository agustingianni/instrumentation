#include <iostream>

using namespace std;

class ClassA
{
public:
	ClassA();
	void method1(void *ptr);
	void method2();
	void method3();
private:
	int field1;
	int field2;
	int field3;
	short field4;
	short field5;
};

ClassA::ClassA()
{
	this->field1 = 0x1000;
}

void ClassA::method1(void *ptr)
{
	cout << ptr << endl;
	this->field1 = 0x2000;
	//this->field4 = 0xcafe;
	this->field5 = 0xcaca;

	return;
}

void ClassA::method2()
{
	field2 += 1;
	return;
}

void ClassA::method3()
{
	field3 += 1;
	return;
}

class ClassB
{
public:
	ClassB();
	void method1(void *ptr);
	void method2();
	void method3();
	void method4();
private:
	int field1;
	int field2;
	int field3;
	int field4;
	int field5;
	int field6;
};

ClassB::ClassB()
{
	this->field1 = 0x1000;
}

void ClassB::method1(void *ptr)
{
	cout << ptr << endl;
	this->field1 = 0x4000;
	return;
}

void ClassB::method2()
{
	field2 += 1;
	return;
}

void ClassB::method3()
{
	field3 += 1;
	return;
}
void ClassB::method4()
{
	field4 += 1;
	return;
}

int main(int argc, char **argv)
{
	ClassA *obj = new ClassA();
	obj->method1((void *) 0xcafecafe);
	obj->method2();
	obj->method3();

	delete obj;

	obj = new ClassA();
	obj->method1((void *) 0xdeadc0de);
	delete obj;

	ClassB *obj2 = new ClassB();
	obj2->method1((void *) 0xcafecafe);
	obj2->method2();
	obj2->method3();

	delete obj2;

	obj2 = new ClassB();
	obj2->method3();
	obj2->method4();
	delete obj2;

	return 0;
}

/*
 * test_vtables.cpp
 *
 *  Created on: Mar 9, 2012
 *      Author: agustin
 */

#include <iostream>

using namespace std;

struct A
{
	virtual void f()
	{
		cout << "A::f" << endl;
		ia = 0x12121212;
	}

	virtual void g()
	{
		cout << "A::g" << endl;
		ja = 0x13131313;
	}

	virtual void h()
	{
		cout << "A::h" << endl;
		ka = 0x14141414;
	}

	int ia;
	int ja;
	int ka;
};

struct B: public A
{
	virtual void f()
	{
		cout << "B::f" << endl;
		ia = 0x21212121;
		ib = 0x11111111;
	}

	virtual void g()
	{
		cout << "B::g" << endl;
		ja = 0x31313131;
		jb = 0x22222222;
		ka = 0x33333333;
	}

	int ib;
	int jb;
};

int main(int argc, char **argv)
{
	A *ai = new A();
	ai->f();
	ai->g();
	ai->h();

	B *bi = new B();
	bi->f();
	bi->g();
	bi->h();

	bi->A::f();
	bi->A::g();
	bi->A::h();

	delete ai;
	delete bi;
}


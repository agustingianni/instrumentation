CodeCoverage pintool that creates a log file with information regarding the instructions executed
by a process. The tool works on Windows, Linux and OS X.

This tool aims to facilitate locating interesting parts of a program without incurring in too much
instrumentation overhead. For this reason the pintool can be instructed to only instrument those
modules inside a white-list.

Example usage: Here we run the pintool from the command line and we specify that only the 'test'
image should be instrumented. This improves performance and reduce the amount of information collected.
You can specify as many white-listed images as you want by adding several "-w" arguments to the pintool.

$ pin -t obj-intel64/CodeCoverage.dylib -w test -- ../../../test
CodeCoverage tool by Agustin Gianni (agustingianni@gmail.com)
White-listing image: test
Logging code coverage information to: trace.log
Loaded image: 0x000000010a1df000:0x000000010a1dffff -> test
Loaded image: 0x00007fff65a5c000:0x00007fff65acffff -> dyld
Loaded image: 0x00007fff94b07000:0x00007fff94b5afff -> libc++.1.dylib
Loaded image: 0x00007fff942fa000:0x00007fff942fbfff -> libSystem.B.dylib
Loaded image: 0x00007fff8bf30000:0x00007fff8bf59fff -> libc++abi.dylib
Loaded image: 0x00007fff875ac000:0x00007fff875b0fff -> libcache.dylib

$ ll trace.log
-rw-------  1 anon  staff   3.1K Apr 28 01:01 trace.log

If you want to instrument all the loaded modules you can leave out the "-w" parameter and it will 
trace all the basic blocks. Beware that the resulting log file will be several orders of magnitude
bigger.

$ pin -t obj-intel64/CodeCoverage.dylib -- test
CodeCoverage tool by Agustin Gianni (agustingianni@gmail.com)
White-listed images not specified, instrumenting every module by default.
Logging code coverage information to: trace.log
Loaded image: 0x0000000101bf1000:0x0000000101bf1fff -> test
Loaded image: 0x00007fff6d167000:0x00007fff6d1dafff -> dyld
Loaded image: 0x00007fff94b07000:0x00007fff94b5afff -> libc++.1.dylib
Loaded image: 0x00007fff942fa000:0x00007fff942fbfff -> libSystem.B.dylib
Loaded image: 0x00007fff8bf30000:0x00007fff8bf59fff -> libc++abi.dylib
Loaded image: 0x00007fff875ac000:0x00007fff875b0fff -> libcache.dylib

$ ll trace.log
-rw-------  1 anon  staff   113K Apr 28 00:57 trace.log

As it can be appreciated in the log file, we have both information about the trace hits and information about the
loaded images (in the example some entries were removed for clarity). This is because when importing the
information into IDA Pro we need to accommodate the addresses to the base address in the IDB. Due to ASLR
the addresses won't match.

The format of the log file is very simple. There is one line for each "event" that the pintool investigates:

	1. Basic block hit:
	   H;<bb_start_hex_address>

	2. Library load:
	   L;<library_path>;<library_hex_start_address>;<library_hex_end_address>

# DBI Tools
Collection of tools implemented using pintools aimed to help in the task of reverse engineering.

## Warning
Some of the code is bitrotten due to the fact that mantaining a windows build of a pintool is a very painful experience. Nonetheless, I think that they are a good resource for learning and extending a reversers toolkit.

## Pinnacle
Pinnacle is an online dynamic taint analysis tool that helps an analyst locate interesting parts of a binary, that is the ones that he can influence, be it by using a file or a socket.

The tool is showcased in detail in the paper `Augmenting Vulnerability Analysis of Binary Code` which can be downloaded here [PDF](https://pdfs.semanticscholar.org/01e0/47ba02edaa55f230af2c8e11b5e99499ae50.pdf).

## CodeCoverage
Simple and somewhat fast tool to gather code coverage collection from a running process. What separates this tool from others is that we are thread safe allowing us to trace complex programs like web browsers.

## Recoverer
Data type recovery tool aimed to recover classes/structures used on the heap. More details can be found on the talk `Trace surfing: a tale of data structure recovery and other yerbas.` [PDF](https://www.ekoparty.org/archivo/2012/eko8-Trace_Surfing.pdf).

## Resolver
Resolver pintool that exports a json JSON file with information regarding
interesting bits about the application like VTABLE address, indirect branches
destinations and other stuff.

This tool aims to facilitate the task of the reverse-engineer while reversint big
softwares. While tracing we collect information that can be then imported into IDA
making the IDB more complete.

The first information collected is information about the so called "direct_branches". This
information is collected because sometimes IDA does not detect certain functions in the code.
We log the entry point of the call function and then import it into IDA creating a XREF from
the call point to the call entry point.

The second type of information that we collect is the call point and call destination of
indirect branches. With this information we can resolve the address of instructions like
"call eax", "jmp eax", etc.

The third type of information collected is the "interesting_instructions". Here we simply collect
instructions that are likely to pose security threats. As of now, we collect sign extension instructions
that may lead to sign extension issues, and rep prefixed instructions that are also sometimes source of
interesting bugs. The idea behind this is that the auditor can import this information and
manualy look at the information provided to look for bugs.

The last type of information collected is the address of the VTABLES used by the software. We collect
this information using a pretty stable heuristic pattern followed by most compilers.
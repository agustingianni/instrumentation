all: test_padding pepe test_merge test_vtables test1 test_offsets test_composition test_composition_2 test_custom_alloc test_offsets_2

test_padding: test_padding.cpp
	g++ -o test_padding test_padding.cpp

pepe: pepe.cpp
	g++ -o pepe pepe.cpp

test_merge: test_merge.cpp
	g++ -o test_merge test_merge.cpp

test_vtables: test_vtables.cpp
	g++ -o test_vtables test_vtables.cpp

test1: test1.cpp
	g++ -o test1 test1.cpp

test_offsets: test_offsets.cpp
	g++ -o test_offsets test_offsets.cpp

test_offsets_2: test_offsets_2.cpp
	g++ -o test_offsets_2 test_offsets_2.cpp

test_composition: test_composition.cpp
	g++ -o test_composition test_composition.cpp

test_composition_2: test_composition_2.cpp
	g++ -o test_composition_2 test_composition_2.cpp

test_custom_alloc: test_custom_alloc.cpp
	g++ -o test_custom_alloc test_custom_alloc.cpp


clean:
	-rm -rf *.o *.s pepe test_padding test_merge test_vtables test1 test_offsets test_offsets_2 test_composition test_composition_2 test_custom_alloc


all: memory_check_malloc_overflow.so memory_check_malloc_usefree.so test/test_memory_overflow test/test_memory_usefree

memory_check_malloc_overflow.so: memory_check_malloc_overflow.cc
	g++ memory_check_malloc_overflow.cc -o memory_check_malloc_overflow.so -g -fPIC --shared

memory_check_malloc_usefree.so: memory_check_malloc_usefree.cc
	g++ memory_check_malloc_usefree.cc -o memory_check_malloc_usefree.so -g -fPIC --shared -ldl

test/test_memory_overflow: test/test_memory_overflow.cc
	g++ test/test_memory_overflow.cc -o test/test_memory_overflow -g

test/test_memory_usefree: test/test_memory_usefree.cc
	g++ test/test_memory_usefree.cc -o test/test_memory_usefree -g -lpthread

test_overflow: all
	LD_PRELOAD=./memory_check_malloc_overflow.so test/test_memory_overflow

test_usefree: all
	LD_PRELOAD=./memory_check_malloc_usefree.so test/test_memory_usefree

clean:
	rm -rf memory_check_malloc_overflow.so memory_check_malloc_usefree.so test/test_memory_overflow test/test_memory_usefree

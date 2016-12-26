#include <cstdio>
#include <cassert>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

void test() {
    int fd = open("/dev/random", O_RDONLY);
    assert(fd != -1);

    uint64_t variable = 0;

    ssize_t ret = read(fd, &variable, sizeof(variable));
    assert(ret == sizeof(variable));

    if (variable < 1000) {
        variable += 0xcafecafe;
    } else {
        variable += 0xdeadbeef;
    }

    uint64_t tmp1 = 0;
    uint64_t tmp2 = variable << 2;
    uint64_t tmp3 = variable >> 2;
    uint64_t tmp4 = variable + 2;
    uint64_t tmp5 = variable - 2;
    uint64_t tmp6 = variable * 2;
    uint64_t tmp7 = variable / 2;
    uint64_t tmp8 = variable | 2;
    uint64_t tmp9 = variable & 2;
    uint64_t tmp10 = variable ^ 2;



    return;
}

int main(int argc, char const *argv[]) {
    test();
    return 0;
}

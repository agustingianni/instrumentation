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

    return;
}

int main(int argc, char const *argv[]) {
    test();
    return 0;
}

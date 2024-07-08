#include <stdio.h>
#include <string.h>
#include <ft_custom_pp.h>

int main(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Usage: %s <number-of-bytes-to-consume>\n", argv[0]);
        return 1;
    }

    size_t nbytes = atoi(argv[1]);
    uint8_t buffer[nbytes];
    memset(buffer, 0x00, nbytes);

    __ft_get_bytes(buffer, nbytes);

    for (int i = 0; i < nbytes; i++) {
        printf("%02x\n", buffer[i]);
    }

    return 0;
}
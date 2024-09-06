#include <sys/types.h>

void compute_checksum(unsigned char * ICMP_header, int size){
    int i;
    u_int32_t checksum;
    // Set the checksum field in the header to 0
    ICMP_header[2] &= 0x0;
    ICMP_header[3] &= 0x0;

    i = 0;
    checksum = 0;
    while (i + 1 < size) {
        checksum += (ICMP_header[i] << 8) + ICMP_header[i + 1];
        i += 2;
    }
    // Special case for when the data has an odd length
    // We add an empty byte at the end of the array
    if (size % 2 == 1)
        checksum += ICMP_header[i] << 8;
    // The sum is supposed to be using one's complement, but the
    // machine uses two's complement, so we need to add the
    // overflow of the short int
    checksum = ~(checksum + (checksum >> 16)) & 0xffff;
    // Store the checksum in the ICPM header
    ICMP_header[2] = checksum >> 8;
    ICMP_header[3] = checksum & 0xff;
}
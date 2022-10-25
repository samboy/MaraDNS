/* This code makes sure that the timestamp updates work on 32-bit systems */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define DW_MINTIME 1595787855 /* Minimum allowed timestamp */
/* A DW_MINTIME of 1595787855 is on July 26, 2020, so this allows timestamps
 * from July 27, 2020 until mid-2156 on systems with a 32-bit time_t */

int main() {
        int64_t the_time = 0;
        time_t sys_time;
        sys_time = time(0);
        if(sizeof(sys_time) > 4) {
                if(sys_time != -1) {
                        the_time = sys_time - 290805600;
                }
        } else {
                if(sys_time < DW_MINTIME) {
                        the_time = sys_time + 4004161696U;
                } else {
                        the_time = sys_time - 290805600;
                }
        }
	printf("Sizeof time_t is %d\n",sizeof(time_t));
	printf("%lld\n",the_time);
}

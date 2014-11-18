/* Solaris requires that /dev/tcp, /dev/udp, and /dev/zero are copied to
   the /etc/maradns directory.  This program does just that (alas, a
   shell script which simply does a "mkdir /etc/maradns/dev; cd /dev;
   cp tcp udp zero /etc/maradns/dev" does not work).
*/

/* Some locations */
#define DEV_DIRECTORY "/dev"
#define CHROOT_DEV_DIRECTORY "/etc/maradns/dev"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Copy a device special file from DEV_DIRECTORY to CHROOT_DEV_DIRECTORY
   input: The name of the device (e.g. "zero", "null", "tcp", or "udp")
   output: 1; exit program on error
*/

int copy_device(char *devname) {
    struct stat buf;
    if(chdir(DEV_DIRECTORY) != 0) {
        printf("Can not go to dev directory %s\n",DEV_DIRECTORY);
        exit(1);
        }
    if(stat(devname,&buf) != 0) {
        printf("Can not stat %s/%s\n",DEV_DIRECTORY,devname);
        exit(1);
        }
    if(chdir(CHROOT_DEV_DIRECTORY) != 0) {
        printf("Can not go to MaraDNS chroot dev directory %s\n",
               CHROOT_DEV_DIRECTORY);
        exit(1);
        }
    if(mknod(devname,buf.st_mode,buf.st_rdev) != 0) {
        printf("Can not mknod device %s/%s\n",CHROOT_DEV_DIRECTORY,
               DEV_DIRECTORY);
        exit(2);
        }
    return 1;
    }

main() {
    copy_device("zero");
    copy_device("tcp");
    copy_device("udp");
    }


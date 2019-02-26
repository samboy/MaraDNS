/* Donated to the public domain 2007 by Sam Trenholme
 *
 * This software is provided 'as is' with no guarantees of correctness or
 * fitness for purpose.
 */

/* This implements RadioGatun[32] (RadioGatun for machines with 32-bit
 * words).
 *
 * Note that there are a couple of differences between the specification and
 * the reference code:
 * 
 * 1) In the spec, the input mapping is b[0,i] = p[i] and a[i + 16] = p[i]
 *    In the reference code, this is b[0,i] ^= p[i] and a[i + 16] ^= p[i]
 *
 * 2) In the spec, the input is padded with "single bit with a value of 1
 *    and zeroes until the length of the result is a multiple of the input 
 *    block length".  
 *    In the reference code, the padding is actually seven zero bits, followed
 *    by a single bit with a value of one, followed by zeroes until we have
 *    a multiple of the input block length.
 *
 * This code is as per the reference code
 */

/* Longest path name */
#define PATH_MAX 32768

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

/* Fileprint: Print a filename, escaping control characters */
void fileprint(char *filename) {
        printf(" ");
	while(*filename != '\0') {
		if((*filename < 32 && *filename >= 0) 
                   || *filename == '~' || *filename == 127) {
			printf("~%02x",*filename);
		} else {
			printf("%c",*filename);	
		}
		filename++;
	}
	printf("\n");
	fflush(stdout);
}

void mill(u_int32_t *a) {
	u_int32_t A[19];
	u_int32_t x;
 	/* The following is the output of the awk script 
         * "make.mill.core" */	
	x = a[0] ^ (a[1] | (~a[2]));
	A[0] = x;
	x = a[7] ^ (a[8] | (~a[9]));
	A[1] = (x >> 1) | (x << 31);
	x = a[14] ^ (a[15] | (~a[16]));
	A[2] = (x >> 3) | (x << 29);
	x = a[2] ^ (a[3] | (~a[4]));
	A[3] = (x >> 6) | (x << 26);
	x = a[9] ^ (a[10] | (~a[11]));
	A[4] = (x >> 10) | (x << 22);
	x = a[16] ^ (a[17] | (~a[18]));
	A[5] = (x >> 15) | (x << 17);
	x = a[4] ^ (a[5] | (~a[6]));
	A[6] = (x >> 21) | (x << 11);
	x = a[11] ^ (a[12] | (~a[13]));
	A[7] = (x >> 28) | (x << 4);
	x = a[18] ^ (a[0] | (~a[1]));
	A[8] = (x >> 4) | (x << 28);
	x = a[6] ^ (a[7] | (~a[8]));
	A[9] = (x >> 13) | (x << 19);
	x = a[13] ^ (a[14] | (~a[15]));
	A[10] = (x >> 23) | (x << 9);
	x = a[1] ^ (a[2] | (~a[3]));
	A[11] = (x >> 2) | (x << 30);
	x = a[8] ^ (a[9] | (~a[10]));
	A[12] = (x >> 14) | (x << 18);
	x = a[15] ^ (a[16] | (~a[17]));
	A[13] = (x >> 27) | (x << 5);
	x = a[3] ^ (a[4] | (~a[5]));
	A[14] = (x >> 9) | (x << 23);
	x = a[10] ^ (a[11] | (~a[12]));
	A[15] = (x >> 24) | (x << 8);
	x = a[17] ^ (a[18] | (~a[0]));
	A[16] = (x >> 8) | (x << 24);
	x = a[5] ^ (a[6] | (~a[7]));
	A[17] = (x >> 25) | (x << 7);
	x = a[12] ^ (a[13] | (~a[14]));
	A[18] = (x >> 11) | (x << 21);
	a[0] = A[0] ^ A[1] ^ A[4];
	a[1] = A[1] ^ A[2] ^ A[5];
	a[2] = A[2] ^ A[3] ^ A[6];
	a[3] = A[3] ^ A[4] ^ A[7];
	a[4] = A[4] ^ A[5] ^ A[8];
	a[5] = A[5] ^ A[6] ^ A[9];
	a[6] = A[6] ^ A[7] ^ A[10];
	a[7] = A[7] ^ A[8] ^ A[11];
	a[8] = A[8] ^ A[9] ^ A[12];
	a[9] = A[9] ^ A[10] ^ A[13];
	a[10] = A[10] ^ A[11] ^ A[14];
	a[11] = A[11] ^ A[12] ^ A[15];
	a[12] = A[12] ^ A[13] ^ A[16];
	a[13] = A[13] ^ A[14] ^ A[17];
	a[14] = A[14] ^ A[15] ^ A[18];
	a[15] = A[15] ^ A[16] ^ A[0];
	a[16] = A[16] ^ A[17] ^ A[1];
	a[17] = A[17] ^ A[18] ^ A[2];
	a[18] = A[18] ^ A[0] ^ A[3];
	a[0] ^= 1;
}

/* The following is the output of "make.belt.core" */
belt_00(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[12];
	q1 = b[25];
	q2 = b[38];
	b[0] ^= a[1];
	b[14] ^= a[2];
	b[28] ^= a[3];
	b[3] ^= a[4];
	b[17] ^= a[5];
	b[31] ^= a[6];
	b[6] ^= a[7];
	b[20] ^= a[8];
	b[34] ^= a[9];
	b[9] ^= a[10];
	b[23] ^= a[11];
	b[37] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_01(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[11];
	q1 = b[24];
	q2 = b[37];
	b[12] ^= a[1];
	b[13] ^= a[2];
	b[27] ^= a[3];
	b[2] ^= a[4];
	b[16] ^= a[5];
	b[30] ^= a[6];
	b[5] ^= a[7];
	b[19] ^= a[8];
	b[33] ^= a[9];
	b[8] ^= a[10];
	b[22] ^= a[11];
	b[36] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_02(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[10];
	q1 = b[23];
	q2 = b[36];
	b[11] ^= a[1];
	b[25] ^= a[2];
	b[26] ^= a[3];
	b[1] ^= a[4];
	b[15] ^= a[5];
	b[29] ^= a[6];
	b[4] ^= a[7];
	b[18] ^= a[8];
	b[32] ^= a[9];
	b[7] ^= a[10];
	b[21] ^= a[11];
	b[35] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_03(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[9];
	q1 = b[22];
	q2 = b[35];
	b[10] ^= a[1];
	b[24] ^= a[2];
	b[38] ^= a[3];
	b[0] ^= a[4];
	b[14] ^= a[5];
	b[28] ^= a[6];
	b[3] ^= a[7];
	b[17] ^= a[8];
	b[31] ^= a[9];
	b[6] ^= a[10];
	b[20] ^= a[11];
	b[34] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_04(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[8];
	q1 = b[21];
	q2 = b[34];
	b[9] ^= a[1];
	b[23] ^= a[2];
	b[37] ^= a[3];
	b[12] ^= a[4];
	b[13] ^= a[5];
	b[27] ^= a[6];
	b[2] ^= a[7];
	b[16] ^= a[8];
	b[30] ^= a[9];
	b[5] ^= a[10];
	b[19] ^= a[11];
	b[33] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_05(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[7];
	q1 = b[20];
	q2 = b[33];
	b[8] ^= a[1];
	b[22] ^= a[2];
	b[36] ^= a[3];
	b[11] ^= a[4];
	b[25] ^= a[5];
	b[26] ^= a[6];
	b[1] ^= a[7];
	b[15] ^= a[8];
	b[29] ^= a[9];
	b[4] ^= a[10];
	b[18] ^= a[11];
	b[32] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_06(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[6];
	q1 = b[19];
	q2 = b[32];
	b[7] ^= a[1];
	b[21] ^= a[2];
	b[35] ^= a[3];
	b[10] ^= a[4];
	b[24] ^= a[5];
	b[38] ^= a[6];
	b[0] ^= a[7];
	b[14] ^= a[8];
	b[28] ^= a[9];
	b[3] ^= a[10];
	b[17] ^= a[11];
	b[31] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_07(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[5];
	q1 = b[18];
	q2 = b[31];
	b[6] ^= a[1];
	b[20] ^= a[2];
	b[34] ^= a[3];
	b[9] ^= a[4];
	b[23] ^= a[5];
	b[37] ^= a[6];
	b[12] ^= a[7];
	b[13] ^= a[8];
	b[27] ^= a[9];
	b[2] ^= a[10];
	b[16] ^= a[11];
	b[30] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_08(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[4];
	q1 = b[17];
	q2 = b[30];
	b[5] ^= a[1];
	b[19] ^= a[2];
	b[33] ^= a[3];
	b[8] ^= a[4];
	b[22] ^= a[5];
	b[36] ^= a[6];
	b[11] ^= a[7];
	b[25] ^= a[8];
	b[26] ^= a[9];
	b[1] ^= a[10];
	b[15] ^= a[11];
	b[29] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_09(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[3];
	q1 = b[16];
	q2 = b[29];
	b[4] ^= a[1];
	b[18] ^= a[2];
	b[32] ^= a[3];
	b[7] ^= a[4];
	b[21] ^= a[5];
	b[35] ^= a[6];
	b[10] ^= a[7];
	b[24] ^= a[8];
	b[38] ^= a[9];
	b[0] ^= a[10];
	b[14] ^= a[11];
	b[28] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_10(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[2];
	q1 = b[15];
	q2 = b[28];
	b[3] ^= a[1];
	b[17] ^= a[2];
	b[31] ^= a[3];
	b[6] ^= a[4];
	b[20] ^= a[5];
	b[34] ^= a[6];
	b[9] ^= a[7];
	b[23] ^= a[8];
	b[37] ^= a[9];
	b[12] ^= a[10];
	b[13] ^= a[11];
	b[27] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_11(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[1];
	q1 = b[14];
	q2 = b[27];
	b[2] ^= a[1];
	b[16] ^= a[2];
	b[30] ^= a[3];
	b[5] ^= a[4];
	b[19] ^= a[5];
	b[33] ^= a[6];
	b[8] ^= a[7];
	b[22] ^= a[8];
	b[36] ^= a[9];
	b[11] ^= a[10];
	b[25] ^= a[11];
	b[26] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

belt_12(u_int32_t *a, u_int32_t *b) {
	u_int32_t q0, q1, q2;
	q0 = b[0];
	q1 = b[13];
	q2 = b[26];
	b[1] ^= a[1];
	b[15] ^= a[2];
	b[29] ^= a[3];
	b[4] ^= a[4];
	b[18] ^= a[5];
	b[32] ^= a[6];
	b[7] ^= a[7];
	b[21] ^= a[8];
	b[35] ^= a[9];
	b[10] ^= a[10];
	b[24] ^= a[11];
	b[38] ^= a[12];
	mill(a);
	a[13] ^= q0;
	a[14] ^= q1;
	a[15] ^= q2;
}

void round(u_int32_t *a, u_int32_t *b, int offset) {
	switch(offset) {
		case 0:
			belt_00(a,b);
			return;
		case 1:
			belt_01(a,b);
			return;
		case 2:
			belt_02(a,b);
			return;
		case 3:
			belt_03(a,b);
			return;
		case 4:
			belt_04(a,b);
			return;
		case 5:
			belt_05(a,b);
			return;
		case 6:
			belt_06(a,b);
			return;
		case 7:
			belt_07(a,b);
			return;
		case 8:
			belt_08(a,b);
			return;
		case 9:
			belt_09(a,b);
			return;
		case 10:
			belt_10(a,b);
			return;
		case 11:
			belt_11(a,b);
			return;
		case 12:
			belt_12(a,b);
			return;
	}
}

/* Specification says we directly assign values from the input in to the belt
 * and mill; reference code, however XORs the input with the values already
 * in the belt and mill */
int input_map(u_int32_t *a, u_int32_t *b, char *filename, int *o)  {
	u_int32_t p[3];
	int q, c, r, w;
	int done = 0;
	int readed = 0, counter;
	char v[12];
	FILE *desc;
	
	/* Open the file */
	if((desc = fopen(filename,"rb")) == NULL) {
		return 1;
	}

	for(;;) {	
		int offset = 0;
		readed = fread(v,1,12,desc);
		p[0] = p[1] = p[2] = 0;
		offset = 0;
		for(r = 0; r < 3; r++) {
			for(q = 0; q < 4; q++) {
				int x;
				x = (int)*(v + offset);
				x = x & 0xff;
				if(offset >= readed) {
					done = 1;
					/* Spec says this should have a value
                                         * of 0x80; reference code gives this
                                         * a value of 1.  This is IMHO a bug
                                         * in the reference code. */
					x = 1;
				}
				offset++;
				p[r] |= x << (q * 8);
				if(done == 1) {
					for(c = 0; c < 3; c++) {
						w = 13 - *o;
						if(w == 13) {w=0;}
						b[w + c * 13] ^= p[c];	
						a[16 + c] ^= p[c];
					}
					round(a,b,*o);
					*o += 1;
					if(*o == 13) {*o = 0;}
					fclose(desc);
					return 0;
				}
			}
		}
		for(c = 0; c < 3; c++) {
			w = 13 - *o;
			if(w == 13) {w = 0;}
			b[w + c * 13] ^= p[c];	
			a[16 + c] ^= p[c];
		}
		round(a,b,*o);
		*o += 1;
		if(*o == 13) {*o = 0;}
	}	
	fclose(desc);
			
}
/* Hashfile: Hash a single file */

void hashfile(char *filename) {
	u_int32_t a[19], b[39];
	int c;
	int o = 0;
	/* Initialize the mill */
	for(c = 0 ; c < 19 ; c++) {
		a[c] = 0;
	}
	/* Initialize the belt */
	for(c = 0; c < 39; c++) {
		b[c] = 0;
	}
	/* Input mapping */
	if(input_map(a,b,filename,&o) == 1) {
		printf("[[UNABLE TO OPEN FILE]]");
		for(c=0;c<41;c++) {printf(" ");}
		fileprint(filename);
		return;
	}
	/* End injection */
	for(c = 0; c < 16; c++) {
		round(a,b,o);
		o++;
		if(o > 12){o=0;}
	}
	/* End mangling */
	for(c = 0; c < 4; c++) {
		unsigned char d,e,f,g;
		round(a,b,o);
		o++;
		if(o > 12){o=0;}
		d = a[1] & 0xff;
		e = (a[1] >> 8) & 0xff;
		f = (a[1] >> 16) & 0xff;
		g = (a[1] >> 24) & 0xff;
		printf("%02x%02x%02x%02x",d,e,f,g);
		d = a[2] & 0xff;
		e = (a[2] >> 8) & 0xff;
		f = (a[2] >> 16) & 0xff;
		g = (a[2] >> 24) & 0xff;
		printf("%02x%02x%02x%02x",d,e,f,g);
	}
	fileprint(filename);
}

/* The routine that handles directories */
void dirhandle(char *dir) {
    char path[PATH_MAX];
    DIR *wd;
    struct dirent *f;
    struct stat s;
    wd = opendir(dir);
    if(wd == NULL) {
	 int c;
	 printf("[[UNABLE TO OPEN DIRECTORY]]");
	 for(c=0;c<36;c++) {printf(" ");}
         fileprint(dir);
         return;
         }
    f = readdir(wd);
    while(f != NULL) {
        strncpy(path,dir,PATH_MAX - 10);
        strncat(path,"/",1);
	if((strlen(path) + 10 + strlen(f->d_name)) >= PATH_MAX) {
		return;
	}
	if(strcmp(f->d_name,".") != 0 &&
           strcmp(f->d_name,"..") != 0) {
	    strcat(path,f->d_name);
            lstat(path,&s);
	    /* We don't follow links to directories, in order to avoid
             * circular chains */
	    if(S_ISDIR(s.st_mode) && !S_ISLNK(s.st_mode)) {
		dirhandle(path);
	    } else if(S_ISREG(s.st_mode)) {
    		hashfile(path);
            }
        }
        f = readdir(wd);
        }
    closedir(wd);
    }

/* The main routine.  This reads files/directories specified on the 
   command line, then makes a hash out of that file. */

main(int argc, char **argv) {
    int counter, q;
    struct stat s;
    /* Check the command line argument */
    if(argc < 2) {
        if(argc >= 1) {
            printf("Usage: %s {filename}\n",argv[0]);
	    exit(1);
	    }
        else {
	    printf("Usage: <this program> {filename}\n");
	    exit(2);
	    }
        }
    for(counter = 1; counter < argc; counter++) {	
        lstat(argv[counter],&s);
	if(S_ISDIR(s.st_mode) && !S_ISLNK(s.st_mode)) {
		dirhandle(argv[counter]);
	} else if(S_ISREG(s.st_mode)) {
    		hashfile(argv[counter]);
        }
    }
}


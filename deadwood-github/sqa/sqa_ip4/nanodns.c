/*Placed in the public domain by Sam Trenholme*/
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#define Z struct sockaddr
#define Y sizeof(d)
int main(int a,char **b){uint32_t i;char q[512]
,p[17]="\xc0\f\0\x01\0\x01\0\0\0\0\0\x04";if(a>
1){struct sockaddr_in d;socklen_t f=511;bzero(&
d,Y);a=socket(AF_INET,SOCK_DGRAM,0);*((uint32_t
*)(p+12))=inet_addr(b[1]);d.sin_family=AF_INET;
d.sin_port=htons(53);
d.sin_addr.s_addr=inet_addr("127.0.0.2");
bind(a,(Z*)&d,Y);for(;;){i
=recvfrom(a,q,255,0,(Z*)&d,&f);if(i>9&&q[2]>=0)
{q[2]|=128;q[11]?q[3]|=4:1;q[7]++;memcpy(q+i,p,
16);sendto(a,q,i+16,0,(Z*)&d,Y);}}}return 0;}

#include<stdio.h>//RadioGatun
#include<stdint.h>/*32-bit**/
#define b(z) for(c=0;c<z;c++)
uint32_t c,e[42],f[42],g=19,h
=13,n[45],i,j,k;void m(){j=0;
b(12)f[c+c%3*h]^=e[c+1];b(g){
i=c*7%g;k=e[i++];k^=e[i%g]|~e
[(i+1)%g];j=j+c;n[c]=n[c+g]=k
>>j%32|k<<-j%32;}for(i=39;i--
;f[i+1]=f[i])e[i]=n[i]^n[i+1]
^n[i+4];b(3)e[c+h]^=f[c*h]=f[
c*h+h];*e^=1;}int main(int c,
char**v){char*q=v[--c];for(;;
m()){b(3){for(j=0;j<4;){f[c*h
]^=k=(*q?255&*q:1)<<8*j++;e[c
+16]^=k;if(!*q++){b(18)m();b(
8){j=c;b(4)printf("%02x",(e[1
+j%2]>>8*c)&255);c=j;if(c%2)m
();}return 0&puts("");}}}}}//

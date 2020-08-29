#include <unistd.h>
#include <stdio.h>

int main() {
	execve("../../coLunacyDNS",0,0);
	perror("execve"); 
}

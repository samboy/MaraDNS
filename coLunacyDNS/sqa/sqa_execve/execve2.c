#include <unistd.h>
#include <stdio.h>

int main() {
	char *argv[] = { NULL };
	char *env[] = { NULL };
	execve("../../coLunacyDNS",argv,env);
	perror("execve"); 
}

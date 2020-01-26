all:	show_packet_stdout send_packet_stdin truncated

clean:
	rm -f show_packet_stdout send_packet_stdin truncated

show_packet_stdout:	show_packet_stdout.c
	$(CC) $(FLAGS) -Wall -o show_packet_stdout show_packet_stdout.c

send_packet_stdin:	send_packet_stdin.c
	$(CC) $(FLAGS) -Wall -o send_packet_stdin send_packet_stdin.c 

truncated:	truncated.c
	$(CC) $(FLAGS) -Wall -o truncated truncated.c 

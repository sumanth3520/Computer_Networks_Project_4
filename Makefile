all:
	gcc -o tcp_traceroute tcp_traceroute.c

clean:
	rm -f tcp_traceroute

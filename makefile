def:
	gcc -g -fPIC -shared pcap.c -o libpcap.so
	gcc -g -fPIC -shared srcip_filter.c dstip_filter.c protocol.c ldapexpr.c srcport_filter.c dstport_filter.c  -I. -o libfilter-test.so

clean: 
	rm -f *.o libpcap.so libfilter-test.so 


test: def
	"do nothing"


.PHONY: def clean ut test

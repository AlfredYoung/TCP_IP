#include "ARP_Cache_Table.h"
#include "Resource.h"
#include "Ethernet.h"
#include "Network_ARP_send.h"
#include "Network_IPV4_send.h"
#include "Header_Include.h"

u_int8_t ip_buffer[MAX_SIZE];

int main()
{
	//initial the arp_table
	init_arp_table();
	output_arp_table();

	open_device();

	FILE *fp;
	fp = fopen("data.txt", "rb");

	network_ipv4_send(ip_buffer, fp);

	fclose(fp);
	close_device();
	return 0;
}
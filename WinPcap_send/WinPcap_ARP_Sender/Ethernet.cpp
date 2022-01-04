#include "Ethernet.h"
#include "Resource.h"
#include"Network_IPV4_send.h"

u_int32_t crc32_table[256] = { 0 };
u_int32_t size_of_packet = 0;

u_int8_t buffer[MAX_SIZE];
extern pcap_t *handle;
extern u_int8_t local_mac[6];
extern int ethernet_upper_len;

void generate_crc32_table()
{
	int i, j;
	u_int32_t crc;
	for (i = 0; i < 256; i++)
	{
		crc = i;
		for (j = 0; j < 8; j++)
		{
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc >>= 1;
		}
		crc32_table[i] = crc;
	}
}

u_int32_t calculate_crc(u_int8_t *buffer, int len)
{
	int i;
	u_int32_t crc;
	crc = 0xffffffff;
	for (i = 0; i < len; i++)
	{
		crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
	}
	crc ^= 0xffffffff;
	return crc;
}


void load_ethernet_header(u_int8_t *destination_mac,u_int16_t ethernet_type)
{
	struct ethernet_header *hdr = (struct ethernet_header *)buffer;
	size_of_packet = 0;
	// add destination mac address
	hdr->destination_mac[0] = destination_mac[0];
	hdr->destination_mac[1] = destination_mac[1];
	hdr->destination_mac[2] = destination_mac[2];
	hdr->destination_mac[3] = destination_mac[3];
	hdr->destination_mac[4] = destination_mac[4];
	hdr->destination_mac[5] = destination_mac[5];

	//add source mac address
	hdr->source_mac[0] = local_mac[0];
	hdr->source_mac[1] = local_mac[1];
	hdr->source_mac[2] = local_mac[2];
	hdr->source_mac[3] = local_mac[3];
	hdr->source_mac[4] = local_mac[4];
	hdr->source_mac[5] = local_mac[5];

	// add source typy
	hdr->ethernet_type = htons(ethernet_type);

	// caculate the size of packet now
	size_of_packet += sizeof(ethernet_header);
}

int load_ethernet_data(u_int8_t *buffer, u_int8_t *upper_buffer, int len)
{
	if (len > 1500)
	{
		printf("IP buffer is too large. So we stop the procedure.");
		return -1;
	}

	int i;
	for (i = 0; i < len; i++)
	{
		*(buffer + i) = *(upper_buffer + i);
	}

	//add a serial 0 at the end
	while (len < 46)
	{
		*(buffer + len) = 0;
		len++;
	}
    
    //generate_crc32_table();
	u_int32_t crc = calculate_crc(buffer, len);

	*(u_int32_t *)(buffer + len) = crc;
	size_of_packet += len + 4;
	return 1;
}

int ethernet_send_packet(u_int8_t *upper_buffer,u_int8_t *destination_mac,u_int16_t ethernet_type)
{
	load_ethernet_header(destination_mac, ethernet_type);
	load_ethernet_data(buffer + sizeof(struct ethernet_header), upper_buffer, ethernet_upper_len);

	if (pcap_sendpacket(handle, (const u_char *)buffer, size_of_packet) != 0)
	{
		printf("Sending failed..\n");
		return -1;
	}
	else
	{
		printf("Sending Succeed..\n");
		return 1;
	}
}


void open_device()
{
	char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];

	device = pcap_lookupdev(error_buffer);
	//printf("%s\n", device);
	handle = pcap_open_live(device, 65536, 1, 1000, error_buffer);
	//pcap_t* handle;
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int i = 0;
	int inum;
	//char error_buffer[PCAP_ERRBUF_SIZE];

	// get the all network adapter handle 

	if (pcap_findalldevs(&alldevs, error_buffer) == -1)
	{
		printf("%s\n", error_buffer);
	}


	/* Print the list of all network adapter information */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);



	/* Open the adapter */
	if ((handle = pcap_open_live(d->name, // name of the device
		65536, // portion of the packet to capture.65536 grants that the whole packet will be captured on/// all the MACs.
		1, // promiscuous mode
		1000, // read timeout
		error_buffer // error buffer
	)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
	}


	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
	}
	generate_crc32_table();
}
void close_device()
{
	pcap_close(handle);
}

//broadcast and local is acceptable
int is_accept_ethernet_packet(struct ethernet_header *ethernet_hdr)
{
	int i;
	for (i = 0; i < 6; i++)
	{
		if (ethernet_hdr->destination_mac[i] != 0xff)
			break;
	}
	if (i == 6)
	{
		printf("It's broadcast packet.\n");
		return 1;
	}

	for (i = 0; i < 6; i++)
	{
		if (ethernet_hdr->destination_mac[i] != local_mac[i])
			break;
	}

	if (i == 6)
	{
		printf("It's sended to my pc.\n");
		return 1;
	}
	return 0;
}
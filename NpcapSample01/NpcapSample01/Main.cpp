/////////////////////////////////////////////////////////////////////////////

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <pcap.h>
#include <string>
#include <map>
#include <Winsock2.h>
#pragma comment(lib, "Ws2_32.lib")

/////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)

/////////////////////////////////////////////////////////////////////////////

typedef struct _ETHER_HEADER
{
	char Dst[6];
	char Src[6];
	short Type;
} H_ETHER;

/////////////////////////////////////////////////////////////////////////////

typedef struct _H_IP
{
	unsigned char	IHL : 4;		//Bit field
	unsigned char	VER : 4;		//Bit field
	unsigned char	ToS;
	unsigned short	Length;
	unsigned short	ID;
	unsigned short	Frag;
	unsigned char	TTL;
	unsigned char	Protocol;
	unsigned short	Checksum;
	unsigned char	SrcAddr[4];
	unsigned char	DstAddr[4];
} H_IP;

/////////////////////////////////////////////////////////////////////////////

typedef struct _H_TCP
{
	unsigned short	SrcPort;
	unsigned short	DstPort;
	unsigned int	nSeq;
	unsigned int	nAck;
	unsigned char	DataOffset;
	unsigned char	FIN : 1;
	unsigned char	SYN : 1;
	unsigned char	RST : 1;
	unsigned char	PSH : 1;
	unsigned char	ACK : 1;
	unsigned char	URG : 1;
	unsigned char	ECE : 1;
	unsigned char	CWR : 1;
	unsigned short	WindowSize;
	unsigned short	Checksum;
	unsigned short	UrgPointer;
} H_TCP;

/////////////////////////////////////////////////////////////////////////////

typedef struct _USER_PACKET
{
	u_long nSeq;
	u_long nAck;
	u_short nPayload;
} USER_PACKET;

/////////////////////////////////////////////////////////////////////////////

#pragma pack(pop)

/////////////////////////////////////////////////////////////////////////////

void makeKey(H_IP*, std::string&);

/////////////////////////////////////////////////////////////////////////////

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	//struct tm *ltime;
	//char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	//time_t local_tv_sec;

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}

	/* Print the list */
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
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
						// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* Retrieve the packets */
	int res;
	std::map<std::string, std::multimap<u_long, USER_PACKET>*> packet_talbe;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		// frame:14, IP:20, TCP:20
		if (res == 0 || header->len < 54) continue;

		const short nIPv4 = 0x0008;
		H_ETHER *pEther = (H_ETHER*)pkt_data;
		if (pEther->Type != nIPv4) continue;

		const u_char nTCP_TYPE = 0x06;
		H_IP *pIP = (H_IP*)(pkt_data + +sizeof(H_ETHER));
		if (pIP->Protocol != nTCP_TYPE) continue;

		// key = "src-ip : src-port | dst-ip : dst-port"
		std::string key;
		makeKey(pIP, key);
		auto tcpStream = packet_talbe.find(key);

		H_TCP *pTCP = (H_TCP*)(pkt_data + sizeof(H_ETHER) + pIP->IHL * 4);

		USER_PACKET userPacket;
		if (pTCP->SYN == 1 && pTCP->ACK == 0 && tcpStream == packet_talbe.end()) // 연결시도
		{
			//printf("[SYN:1, ACK:0] %s\n", key.c_str());

			//std::multimap<u_long, USER_PACKET> *SeqAckStream = new std::multimap<u_long, USER_PACKET>();
			auto packetStream = new std::multimap<u_long, USER_PACKET>();

			userPacket.nSeq = ntohl(pTCP->nSeq);
			userPacket.nAck = ntohl(pTCP->nAck);
			userPacket.nPayload = header->len - pIP->IHL * 4 - ((pTCP->DataOffset >> 4) & 0x0f) * 4 - 14;

			packetStream->insert(std::pair<u_long, USER_PACKET>(userPacket.nSeq, userPacket));

			packet_talbe.insert(std::pair<std::string, std::multimap<u_long, USER_PACKET>*>(key, packetStream));
		}
		else if (pTCP->SYN == 1 && pTCP->ACK == 1 && tcpStream == packet_talbe.end()) //연결 응답
		{
			//printf("[SYN:1, ACK:1] %s\n", key.c_str());
			auto packetStream = new std::multimap<u_long, USER_PACKET>();

			userPacket.nSeq = ntohl(pTCP->nSeq);
			userPacket.nAck = ntohl(pTCP->nAck);
			userPacket.nPayload = header->len - pIP->IHL * 4 - ((pTCP->DataOffset >> 4) & 0x0f) * 4 - 14;

			packetStream->insert(std::pair<u_long, USER_PACKET>(userPacket.nSeq, userPacket));

			packet_talbe.insert(std::pair<std::string, std::multimap<u_long, USER_PACKET>*>(key, packetStream));
		}
		else if (tcpStream != packet_talbe.end())
		{
			userPacket.nSeq = ntohl(pTCP->nSeq);
			userPacket.nAck = ntohl(pTCP->nAck);
			userPacket.nPayload = header->len - pIP->IHL * 4 - ((pTCP->DataOffset >> 4) & 0x0f) * 4 - 14;
			tcpStream->second->insert(std::pair<u_long, USER_PACKET>(userPacket.nSeq, userPacket));
		}
		else
		{
			// 수집 제외
			//printf("[SYN:%d, ACK:%d] %s\n", pTCP->SYN, pTCP->ACK, key.c_str());
		}

		if (packet_talbe.size() >= 50) break;
	}

	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	//출력
	for (auto i = packet_talbe.begin(); i != packet_talbe.end(); ++i)
	{
		printf("\n/////////////////////////////////////////////////////////////////////////////\n\n");

		printf("key : %s\n", i->first.c_str());
		for (auto p = i->second->begin(); p != i->second->end(); ++p)
		{
			printf
			(
				"Seq(%lu), Ack(%lu), Payload(%d)\n",
				p->second.nSeq,
				p->second.nAck,
				p->second.nPayload
			);
		}
	}

	//삭제
	for (auto i = packet_talbe.begin(); i != packet_talbe.end(); ++i)
	{
		i->second->clear();
		delete i->second;
	}

	packet_talbe.clear();

	pcap_close(adhandle);
	return 0;
}

/////////////////////////////////////////////////////////////////////////////

void makeKey(H_IP *pIP, std::string &key)
{
	H_TCP *pTCP = (H_TCP*)((u_int)pIP + pIP->IHL * 4);
	key = inet_ntoa(*(PIN_ADDR)pIP->SrcAddr);
	key += ":";
	key += std::to_string(ntohs(pTCP->SrcPort));
	key += "|";
	key += inet_ntoa(*(PIN_ADDR)pIP->DstAddr);
	key += ":";
	key += std::to_string(ntohs(pTCP->DstPort));
}

/////////////////////////////////////////////////////////////////////////////
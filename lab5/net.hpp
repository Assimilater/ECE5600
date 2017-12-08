#pragma once

typedef unsigned char byte;
extern int chksum(byte* s, int n, int i);

// macro converts byte[] into ushort, uint
#define BUFF_UINT16(buff, i) (buff[i + 0] << 8 | buff[i + 1] << 0)
#define BUFF_UINT32(buff, i) (buff[i + 0] << 24 | buff[i + 1] << 16 | buff[i + 2] << 8 | buff[i + 3] << 0)

struct ipmac
{
	byte mac[6];
	byte ip[4];
};

struct net_device
{
	union
	{
		ipmac arp_cache_self;
		struct
		{
			byte mac[6];
			byte ip[4];
		};
	};
	byte subnet_mask[4];
	byte default_gateway[4];
};

//----------------------------------------------------------------------------+
// Ethernet 802.3/DIX frames                                                  |
struct ether_header
{
	byte dst[6];
	byte src[6];
	union
	{
		byte len[2];
		byte prot[2];
	};
};
struct ether_frame
{
	ether_header header;
	byte data[1500];
};

ether_frame* make_frame(byte* dst, unsigned short prot, byte* data, int n);
//----------------------------------------------------------------------------+

//----------------------------------------------------------------------------+
// ARP                                                                        |
struct arp_header
{
	byte hwtype[2];
	byte prottype[2];
	byte hwlength;
	byte protlength;
	byte opcode[2];
};

struct arp_frame
{
	arp_header header;
	byte data[1500 - sizeof(arp_header)];
};
ipmac* retrieveArpCache(byte* value);
void saveArpCache(ipmac* value);
void pingARP(byte* ip);
//----------------------------------------------------------------------------+

//----------------------------------------------------------------------------+
// IP                                                                         |
struct ip_header
{
	byte ver_ihl;
	byte dscp;
	
	byte length[2];
	byte ident[2];
	
	byte frag[2];
	
	byte ttl;
	byte prot;
	byte crc[2];
	byte src[4];
	byte dst[4];
};

struct ip_frame
{
	ip_header header;
	byte data[1500 - sizeof(ip_header)];
};
void sendIPv4Packet(byte* ip, byte prot, byte* payload, int n);
//----------------------------------------------------------------------------+

//----------------------------------------------------------------------------+
// ICMP                                                                       |
struct icmp_header
{
	byte type;
	byte code;
	byte crc[2];
	union
	{
		byte header[4];
		struct
		{
			byte ident[2];
			byte seqno[2];
		} echo;
	};
};

struct icmp_frame
{
	icmp_header header;
	byte data[1500 - sizeof(ip_header) - sizeof(icmp_header)];
};
void pingICMP(byte* ip, byte* data, int n);
//----------------------------------------------------------------------------+

#define ETHER_PROT_IPV4         0x0800
#define ETHER_PROT_ARP          0x0806

void arp_handler(byte* packet, int n, ether_header* header);

void ip_handler(byte* packet, int n, ether_header* header);

#define IPV4_PROT_ICMP          0x01
void icmp_handler(byte* packet, int n, ip_header* header);

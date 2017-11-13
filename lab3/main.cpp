#include "frameio.hpp"
#include "message_queue.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <unordered_map>

#include "net.hpp"

// device name must be hard-coded
frameio net("enp3s0");

net_device me = 
{
	0, 0, 0, 0, 0, 0, // mac copied at start of main()
	192, 168, 1, 30,  // ip              must be hard-coded
	255, 255, 255, 0, // subnet mask     must be hard-coded
	192, 168, 1, 1,   // default gateway must be hard-coded
};

std::unordered_map<int, ipmac*> arp_cache;
inline int hash_ip(byte* ip)
{
	static const int hash_mask = ~BUFF_UINT32(me.subnet_mask, 0);
	int ip4 = BUFF_UINT32(ip, 0);
	int key = ip4 & hash_mask;
	return key;
}
ipmac* retrieveArpCache(byte* ip)
{
	int key = hash_ip(ip);
	auto search = arp_cache.find(key);
	if (search != arp_cache.end()) {
		return search->second;
	}
	return NULL;
}
void saveArpCache(ipmac* value)
{
	ipmac* found = retrieveArpCache(value->ip);
	if (found == NULL)
	{
		// insert
		ipmac* copy = (ipmac*)malloc(sizeof(ipmac));
		memcpy(copy, value, sizeof(ipmac));
		int key = hash_ip(copy->ip);
		arp_cache.insert({key, copy});
	}
	else
	{
		// update
		memcpy(found, value, sizeof(ipmac));
	}
}

// message queue for the sending ether_frames
message_queue send_queue;
void* send_thread(void* args)
{
	int n;
	ether_frame frame;
	event_kind event;
	while(1)
	{
		n = send_queue.recv(&event, &frame, sizeof(ether_frame));
		net.send_frame(&frame, n);
	}
}

void* receive_thread(void* args)
{
	ether_frame frame;
	
	while(1)
	{
		int n = net.recv_frame(&frame, sizeof(ether_frame));
		if (n < 42) continue; // bad frame!
		switch (BUFF_UINT16(frame.header.prot, 0))
		{
			case ETHER_PROT_IPV4:
				ip_handler(frame.data, n - sizeof(ether_header), &(frame.header));
				break;
				
			case ETHER_PROT_ARP:
				arp_handler(frame.data, n - sizeof(ether_header), &(frame.header));
				break;
		}
	}
}

ether_frame* make_frame(byte* dst, unsigned short prot, byte* data, int n)
{
	ether_frame* out = (ether_frame*)malloc(n + sizeof(ether_header));
	memcpy(out->header.dst, dst, 6);
	memcpy(out->header.src, me.mac, 6);
	out->header.prot[0] = (prot & 0xFF00) >> 8;
	out->header.prot[1] = (prot & 0x00FF) >> 0;
	memcpy(out->data, data, n);
	return out;
}

void arp_handler(byte* packet, int n, ether_header* header)
{
	arp_frame* frame = (arp_frame*)packet;

	switch (BUFF_UINT16(frame->header.opcode, 0))
	{
		case 1: // Request
			saveArpCache(((ipmac*)frame->data) + 0);
			if (frame->data[16] == me.ip[0] &&
				frame->data[17] == me.ip[1] &&
				frame->data[18] == me.ip[2] &&
				frame->data[19] == me.ip[3])
			{
				// Start with a response frame that has a payload exactly matching what we received
				ether_frame* response = make_frame(frame->data, ETHER_PROT_ARP, (byte*)&frame, n);
				arp_frame* response_arp = (arp_frame*)((byte*)(response) + sizeof(ether_header));
				
				// Convert to reply opcode
				response_arp->header.opcode[1] = 2;
				
				// Move the sender info the the target info
				memcpy(response_arp->data + sizeof(ipmac), response_arp->data + 0, sizeof(ipmac));
				
				// Fill the sender info with our info
				memcpy(response_arp->data + 0, &me, sizeof(ipmac));
				
				send_queue.send(PACKET, response, n + sizeof(ether_header));
				free(response);
			}
			break;
			
		case 2: // Reply
			saveArpCache(((ipmac*)frame->data) + 0);
			saveArpCache(((ipmac*)frame->data) + 1);
			break;
	}
}

void ip_handler(byte* packet, int n, ether_header* header)
{
	ip_frame* frame = (ip_frame*)packet;
	
	// Validate the checksum
	if (chksum(packet, sizeof(ip_header), 0) != 0xffff)
	{
		printf("IP message received with bad checksum\n");
		return;
	}
	
	// Don't include any padding in ip packet
	int len = BUFF_UINT16(frame->header.length, 0);
	if (n > len) { n = len; }
	
	// Find the payload
	byte* payload = frame->data;
	int option_bytes = 4 * ((frame->header.ver_ihl & 0x0f) - 5);
	payload = payload + option_bytes;
	int payload_n = n - option_bytes - sizeof(ip_header);
	
	//printf("IP message received, protocol: %i\n", frame->header.prot);
	switch (frame->header.prot)
	{
		case IPV4_PROT_ICMP:
			icmp_handler(payload, payload_n, &(frame->header));
			break;
	}
}

void icmp_handler(byte* packet, int n, ip_header* header)
{
	icmp_frame* frame = (icmp_frame*)packet;
	
	// Validate the checksum
	if (chksum(packet, sizeof(icmp_header) + n, 0) != 0xffff)
	{
		printf("ICMP message received with bad checksum\n");
		return;
	}
	
	//printf("ICMP message received\n");
	switch (frame->header.type)
	{
		case 0x08: // echo (ping) request
			frame->header.type = 0x00; // echo (ping) reply
			frame->header.crc[0] = 0;
			frame->header.crc[1] = 0;
			
			int crc = ~chksum((byte*)frame, n, 0);
			frame->header.crc[0] = (crc & 0xff00) >> 8;
			frame->header.crc[1] = (crc & 0x00ff) >> 0;
			
			sendIPv4Packet(header->src, IPV4_PROT_ICMP, packet, n);
			break;
	}
}

void pingARP(byte* ip)
{
	static arp_frame message = {
		{
			{ 0, 1 },
			{ 8, 0 },
			6, 4,
			{ 0, 1 },
		},
		{ 0 },
	};
	static const int n = sizeof(arp_header) + (2 * sizeof(ipmac));
	
	if (message.data[0] == 0)
	{
		memcpy(message.data, &me, sizeof(ipmac));
	}
	
	ipmac* found = retrieveArpCache(ip);
	if(found == NULL)
	{
		ipmac value = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 };
		memcpy(value.ip, ip, 4);
		memcpy(((ipmac*)(message.data)) + 1, &value, sizeof(ipmac));
	}
	else
	{
		memcpy(((ipmac*)(message.data)) + 1, found, sizeof(ipmac));
	}
	ether_frame* frame = make_frame((byte*)(((ipmac*)(message.data)) + 1), ETHER_PROT_ARP, (byte*)(&message), n);
	send_queue.send(PACKET, frame, n + sizeof(ether_header));
	free(frame);
}

inline byte* hop_ip(byte* ip)
{
	static const int gateway = BUFF_UINT32(me.default_gateway, 0);
	static const int subnet_mask = BUFF_UINT32(me.subnet_mask, 0);
	static const int subnet = subnet_mask & gateway;
	
	int ip4 = BUFF_UINT32(ip, 0);
	if ((ip4 & subnet_mask) == subnet)
	{
		return ip;
	}
	return me.default_gateway;
}
byte* get_mac(byte* ip)
{
	byte* dst_ip = hop_ip(ip);
	ipmac* dst = retrieveArpCache(dst_ip);
	
	int attempts = 4;
	while (dst == NULL && --attempts >= 0)
	{
		pingARP(dst_ip);
		sleep(1);
		dst = retrieveArpCache(dst_ip);
	}
	
	if (dst == NULL)
	{
		printf("Unable to resolve ip address: %i.%i.%i.%i\n", ip[0], ip[1], ip[2], ip[3]);
		return NULL;
	}
	return dst->mac;
}

void sendIPv4Packet(byte* ip, byte prot, byte* payload, int n)
{
	static unsigned short identifier = 0;
	static ip_frame request = { 0 };
	/*
	{
		{
			{ 4, 5 }, // 0x45 // ipv4 optionless header
			{ 0, 0 }, // default dscp
			{ 0x00, 0x00 }, // length (calculated at each call)
			{ 0x00, 0x00 }, // id (calculated at each call)
			{ 2, 0 }, // 0x4000, // no fragmentation
			64, // ttl 64 (seems common for a default)
			0, // protocol: (copied at each call)
			{ 0 }, // checksum (0 to start)
			{ 0 }, // source (0 for now, copied on first call)
			{ 0 }, // destination (copied at each call)
		},
		{ 0 }, // payload (copied at each call)
	};
	*/
	
	// static initializer for request
	if (request.header.ver_ihl == 0)
	{
		//request.header.version = 4;
		//request.header.ihl = 5; // no options
		request.header.ver_ihl = 0x45;
		//request.header.flags = 2; // no fragmentation
		request.header.frag[0] = 0x40;
		request.header.ttl = 64;
		memcpy(request.header.src, me.ip, 4); // copy source ip
	}
	
	byte* dst_mac = get_mac(ip);
	if (dst_mac == NULL) { return; }
	
	++identifier;
	
	int N = sizeof(ip_header) + n;
	ether_frame* frame = make_frame(dst_mac, ETHER_PROT_IPV4, (byte*)(&request), N);
	ip_frame* packet = (ip_frame*)(frame->data);
	memcpy(packet->data, payload, n);
	memcpy(packet->header.dst, ip, 4);
	
	packet->header.length[0] = (N & 0xff00) >> 8;
	packet->header.length[1] = (N & 0x00ff) >> 0;
	
	packet->header.ident[0] = (identifier & 0xff00) >> 8;
	packet->header.ident[1] = (identifier & 0x00ff) >> 0;
	
	packet->header.prot = prot;
	
	int crc = ~chksum((byte*)packet, sizeof(ip_header), 0);
	packet->header.crc[0] = (crc & 0xff00) >> 8;
	packet->header.crc[1] = (crc & 0x00ff) >> 0;
	
	send_queue.send(PACKET, frame, N + sizeof(ether_header));
	free(frame);
}

void pingICMP(byte* ip, byte* data, int n)
{
	static unsigned short identifier = 0;
	static icmp_frame request =
	{
		{
			0x08, // echo (ping) request
			0x00, // code
			{ 0 }, // checksum (computed every call)
			{ 0 }, // header (computed every call)
		},
		{ 0 },
	};
	
	++identifier;
	unsigned short sequence = 0;
	
	memcpy(request.data, data, n);
	int N = n + sizeof(icmp_header);
	
	request.header.crc[0] = 0;
	request.header.crc[1] = 0;
	
	request.header.echo.ident[0] = (identifier & 0xff00) >> 8;
	request.header.echo.ident[1] = (identifier & 0x00ff) >> 0;
	
	request.header.echo.seqno[0] = (sequence & 0xff00) >> 8;
	request.header.echo.seqno[1] = (sequence & 0x00ff) >> 0;
	
	int crc = ~chksum((byte*)(&request), N, 0);
	request.header.crc[0] = (crc & 0xff00) >> 8;
	request.header.crc[1] = (crc & 0x00ff) >> 0;
	
	sendIPv4Packet(ip, IPV4_PROT_ICMP, (byte*)(&request), N);
}

int main()
{
	memcpy(me.mac, net.get_mac(), 6);
	arp_cache[me.ip[3]] = &(me.arp_cache_self);
	
	int err;
	pthread_t rthread, sthread;
	
	// Create the threads
	err = pthread_create(&rthread, NULL, receive_thread, NULL);
	err = pthread_create(&sthread, NULL, send_thread, NULL);
	
	//------------------------------------------------------------------------+
	// main application routine                                               |
	
	byte request[4] = { 192, 168, 1, 30 };
	byte payload[4] = { 0xde, 0xad, 0xbe, 0xef };
	
	while(1) {
		printf("Press enter to ping ...");
		getchar();
		
		//for(int i = 0; i < 5; ++i)
		{
			//request[3] = 10 + i * 5;
			printf("Sending 0xdeadbeef %i.%i.%i.%i\n", request[0], request[1], request[2], request[3]);
			pingICMP(request, payload, 4);
		}
	}
	
	// main application routine                                               |
	//------------------------------------------------------------------------+
	
	// Put main() to sleep until threads exit
	err = pthread_join(rthread, NULL);
	err = pthread_join(sthread, NULL);
	
	return 0;
}

#include "frameio.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

frameio net;                    // gives us access to the raw network
message_queue send_queue;       // message queue for the sending ether_frames
message_queue ip_queue;         // message queue for the IP protocol stack
message_queue arp_queue;        // message queue for the ARP protocol stack

struct ipmac
{
	octet mac[6];
	octet ip[4];
};

ipmac me = { 0, 0, 0, 0, 0, 0, 192, 168, 1, 40 };

ipmac* arp_cache[256] = { 0 };

struct ether_header
{
	octet dst_mac[6];           // destination MAC address
	octet src_mac[6];           // source MAC address
	octet prot[2];              // protocol (or length)
};

struct ether_frame              // handy template for 802.3/DIX frames
{
	ether_header header;
	octet data[1500];           // payload
};

#define ETHER_PROT_IP           0x0800
#define ETHER_PROT_ARP          0x0806

#define BUFF_UINT16(buff, i)    (buff[i + 0] << 8 | buff[i + 1] << 0)

void* receive_thread(void* args)
{
	ether_frame buf;
	
	while(1)
	{
		int n = net.recv_frame(&buf, sizeof(buf));
		if (n < 42) continue; // bad frame!
		switch (BUFF_UINT16(buf.header.prot, 0))
		{
			case ETHER_PROT_IP:
				ip_queue.send(PACKET, buf.data, n - sizeof(ether_header));
				break;
				
			case ETHER_PROT_ARP:
				arp_queue.send(PACKET, buf.data, n - sizeof(ether_header));
				break;
		}
	}
}

void* send_thread(void* args)
{
	int n;
	ether_frame buf;
	event_kind event;
	while(1)
	{
		n = send_queue.recv(&event, &buf, sizeof(buf));
		net.send_frame(&buf, n);
	}
}

ether_frame* make_frame(octet* dst, unsigned short prot, octet* data, int n)
{
	ether_frame* out = (ether_frame*)malloc(n + sizeof(ether_header));
	memcpy(out->header.dst_mac, dst, 6);
	memcpy(out->header.src_mac, me.mac, 6);
	out->header.prot[0] = (prot & 0xFF00) >> 8;
	out->header.prot[1] = (prot & 0x00FF) >> 0;
	memcpy(out->data, data, n);
	return out;
}

struct arp_header
{
	octet hwtype[2];
	octet prottype[2];
	octet hwlength;
	octet protlength;
	octet opcode[2];
};

struct arp_frame
{
	arp_header header;
	octet data[1500 - sizeof(arp_header)];
};

ipmac* retrieveFromCache(ipmac* value)
{
	return arp_cache[value->ip[3]];
}

void saveToCache(ipmac* value)
{
	if (retrieveFromCache(value) == NULL)
	{
		ipmac* copy = (ipmac*)malloc(sizeof(ipmac));
		memcpy(copy, value, sizeof(ipmac));
		arp_cache[value->ip[3]] = copy;
	}
}

void* arp_protocol(void* args)
{
	int n;
	arp_frame buf;
	event_kind event;

	while (1)
	{
		n = arp_queue.recv(&event, &buf, sizeof(buf));
		switch (BUFF_UINT16(buf.header.opcode, 0))
		{
			case 1: // Request
				saveToCache(((ipmac*)buf.data) + 0);
				if (buf.data[16] == me.ip[0] &&
					buf.data[17] == me.ip[1] &&
					buf.data[18] == me.ip[2] &&
					buf.data[19] == me.ip[3])
				{
					// Start with a response frame that has a payload exactly matching what we received
					ether_frame* response = make_frame(buf.data, ETHER_PROT_ARP, (octet*)&buf, n);
					arp_frame* response_arp = (arp_frame*)((octet*)(response) + sizeof(ether_header));
					
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
				saveToCache(((ipmac*)buf.data) + 0);
				saveToCache(((ipmac*)buf.data) + 1);
				break;
		}
	}
}

// assuming value->mac = { ff, ff, ff, ff, ff, ff }
void sendARP(ipmac* value)
{
	ipmac* found = retrieveFromCache(value);
	arp_frame message = {
		{
			{ 0, 1 },
			{ 8, 0 },
			6, 4,
			{ 0, 0 }
		},
		{ 0 },
	};
	if(found == NULL)
	{
		printf("Not Found in cache, sending broadcast request\n");
		message.header.opcode[1] = 1; // request
		memcpy(message.data, &me, sizeof(ipmac));
		memcpy(((ipmac*)(message.data)) + 1, value, sizeof(ipmac));
	}
	else
	{
		printf("Found in cache, sending reply\n");
		message.header.opcode[1] = 2; // reply
		memcpy(message.data, &me, sizeof(ipmac));
		memcpy(((ipmac*)(message.data)) + 1, found, sizeof(ipmac));
	}
	int n = sizeof(arp_header) + (2 * sizeof(ipmac));
	ether_frame* frame = make_frame((octet*)(((ipmac*)(message.data)) + 1), ETHER_PROT_ARP, (octet*)(&message), n);
	send_queue.send(PACKET, frame, n + sizeof(ether_header));
	free(frame);
}

int main()
{
	// Open the shared resource before starting threads
	net.open_net("enp3s0");
	const octet* mymac = net.get_mac();
	me.mac[0] = mymac[0];
	me.mac[1] = mymac[1];
	me.mac[2] = mymac[2];
	me.mac[3] = mymac[3];
	me.mac[4] = mymac[4];
	me.mac[5] = mymac[5];
	
	arp_cache[me.ip[3]] = &me;
	
	int err;
	
	pthread_t rthread, sthread;
	pthread_t arpthread;
	
	// Create the threads
	err = pthread_create(&rthread, NULL, receive_thread, NULL);
	err = pthread_create(&sthread, NULL, send_thread, NULL);
	
	err = pthread_create(&arpthread, NULL, arp_protocol, NULL);
	
	ipmac request = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 192, 168, 1, 0
	};
	
	while(1) {
		printf("Press enter to send batch ...");
		getchar();
		
		for(int i = 0; i < 5; ++i)
		{
			request.ip[3] = 10 + i * 5;
			printf("Sending 192.168.1.%i: ", request.ip[3]);
			sendARP(&request);
		}
	}
	
	// Put main() to sleep until threads exit
	err = pthread_join(rthread, NULL);
	err = pthread_join(sthread, NULL);
	
	err = pthread_join(arpthread, NULL);
	
	return 0;
}

#include "frameio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

frameio net;             // gives us access to the raw network				

struct ether_frame       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
   octet data[1500];     // payload
};

int main()
{
   net.open_net("enp3s0");
   ether_frame buf;
   octet* raw = (octet*)(&buf);
   
   while(1)
   {
      int n = net.recv_frame(&buf,sizeof(buf));
      if ( n < 42 ) continue; // bad frame!
      switch ( buf.prot[0]<<8 | buf.prot[1] )
      {
          case 0x800:
	  case 0x806:
	    printf(
	      "Received Frame: \n"
	      "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x \n"
	      "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x \n\n",
	      raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10],
	      raw[11], raw[12], raw[13], raw[14], raw[15], raw[16], raw[17], raw[18], raw[19], raw[20],
	      raw[21], raw[22], raw[23], raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30],
	      raw[31], raw[32], raw[33], raw[34], raw[35], raw[36], raw[37], raw[38], raw[39], raw[40],
	      raw[41], raw[42]
	  );
	}
   }
   return 0;
}
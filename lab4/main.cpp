#include <string>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFF 2048

int main() {
	unsigned char buff[BUFF] = { 0 };
	
	sockaddr sa;
	sockaddr_in *sin = (sockaddr_in *) &sa;
	int sk = socket(PF_INET, SOCK_STREAM, 0);
	if (sk < 0) { return -1; }
	
	memset(sin,0,sizeof(sa));
	sin->sin_family = PF_INET;
	sin->sin_port = htons(5600);
	sin->sin_addr.s_addr = INADDR_ANY;
	
	if (bind(sk, (struct sockaddr *)sin, sizeof(sa)) < 0) {
		printf("Bind failed\n");
		return -1;
	}
	printf("Bind succeeded\n");
	
	if (listen(sk, 5) < 0) {
		printf("Listen failed\n");
		return -1;
	}
	printf("Listen succeeded\n");
	
	int i = 0;
	int addrlen = sizeof(sa);
	while(1) {
		int recv = accept(sk, (struct sockaddr *)sin, (socklen_t*)&addrlen);
		
		if (recv < 0) {
			printf("Accept failed\n");
			return -1;
		}
		printf("Accept succeeded\n");
		
		int N = read(recv, buff, BUFF);
		printf("Read %i bytes\n", N);
		
		std::fstream fout("tcp_recv_" + std::to_string(i), std::ios::binary | std::ios::out);
		fout.write((char*)buff, N);
		fout.close();
		
		++i;
	}
	
	return 0;
}

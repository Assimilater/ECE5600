lab5: main.cpp net.hpp chksum.o message_queue.o frameio.o
	g++ -std=c++11 main.cpp chksum.o message_queue.o frameio.o -lpthread -g -O0 -o lab5

chksum.o: chksum.c
	g++ chksum.c -c -o chksum.o

message_queue.o: message_queue.cpp message_queue.hpp
	g++ message_queue.cpp -c -o message_queue.o

frameio.o: frameio.cpp frameio.hpp
	g++ frameio.cpp -c -o frameio.o

clean:
	rm *.o
	rm lab5

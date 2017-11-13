lab2: main.cpp util.o frameio.o
	g++ main.cpp util.o frameio.o -lpthread -g -O0 -o lab2

util.o: util.cpp util.h
	g++ util.cpp -c -g -O0 -o util.o

frameio.o: frameio.cpp frameio.h
	g++ frameio.cpp -c -g -O0 -o frameio.o

clean:
	rm *.o
	rm lab2

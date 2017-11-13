lab2: main.cpp util.o frameio.o
	g++ main.cpp util.o frameio.o -lpthread -o lab2

util.o: util.cpp util.h
	g++ util.cpp -c -o util.o

frameio.o: frameio.cpp frameio.h
	g++ frameio.cpp -c -o frameio.o

clean:
	rm *.o
	rm lab2

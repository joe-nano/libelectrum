CXXFLAGS=$(shell pkg-config --cflags libbitcoin) -ggdb
LIBS=$(shell pkg-config --libs libbitcoin libwallet)

default: all

.cpp.o:
	$(CXX) -o $@ -c $< $(CXXFLAGS)

hd: hd.o
	$(CXX) -o $@ $< $(LIBS)

uri: uri.o
	$(CXX) -o $@ $< $(LIBS)

all: hd uri

clean:
	rm -f hd uri
	rm -f *.o

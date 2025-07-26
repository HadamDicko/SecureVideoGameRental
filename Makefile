CXX = g++
CXXFLAGS = -std=c++20 -Wall
OPENSSL_PATH = $(shell brew --prefix openssl@3)
LDFLAGS = -L$(OPENSSL_PATH)/lib -lssl -lcrypto
INCLUDE = -I$(OPENSSL_PATH)/include

all: server

server: server.cpp p1_helper.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o server server.cpp p1_helper.cpp $(LDFLAGS)

clean:
	rm -f server 

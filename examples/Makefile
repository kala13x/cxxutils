CXXFLAGS = -g -O2 -Wall -D_XSOCK_USE_SSL
LIBS = -lcxxutils -lpthread -lssl -lcrypto

statcov:
	$(CXX) $(CFLAGS) -o statcov statcov.cpp $(LIBS)

.PHONY: clean
clean:
	$(RM) statcov $(OBJS)

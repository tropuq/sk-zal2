CXX  = g++
FLAGS  = -Wall -Wextra -Wshadow -std=c++17 -O2
OBJ = utils.o message.o timer.o
OBJ_SERVER = server_class.o semaphore.o
OBJ_CLIENT = client_class.o
PROG = netstore-server netstore-client

all: $(PROG)

utils.o: utils.cc utils.h
	$(CXX) $(FLAGS) $< -c

message.o: message.cc message.h
	$(CXX) $(FLAGS) $< -c

server_class.o: server_class.cc server_class.h utils.h message.h
	$(CXX) $(FLAGS) $< -c

client_class.o: client_class.cc client_class.h utils.h message.h poll.h
	$(CXX) $(FLAGS) $< -c

timer.o: timer.cc timer.h
	$(CXX) $(FLAGS) $< -c

semaphore.o: semaphore.cc semaphore.h
	$(CXX) $(FLAGS) $< -c


netstore-server: server.cc $(OBJ) $(OBJ_SERVER)
	$(CXX) $(FLAGS) $^ -o $@ -lstdc++fs -lboost_program_options -lpthread

netstore-client: client.cc $(OBJ) $(OBJ_CLIENT)
	$(CXX) $(FLAGS) $^ -o $@ -lstdc++fs -lboost_program_options -lpthread

clean:
	rm -f $(PROG) $(OBJ) $(OBJ_SERVER) $(OBJ_CLIENT)

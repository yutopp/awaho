CPPFLAGS = -std=c++14 -Wall -fPIC -Wl,-z,relro,-z,now
LDFLAGS = \
	-lboost_system \
	-lboost_iostreams \
	-lboost_filesystem \
	-lboost_program_options \
	-lboost_regex \
	-lboost_thread \
	-lboost_chrono \
    -lpthread
BIN = awaho
DEPS = $(wildcard src/*.hpp)
SRCS = \
	main.cpp \
	awaho.cpp \
	container_options.cpp
OBJS = $(SRCS:%.cpp=%.o)

vpath %.hpp src
vpath %.cpp src

.PHONY: debug release clean
.DEFAULT: debug

debug: CPPFLAGS +=
debug: LDFLAGS  +=
debug: $(BIN)

release: CPPFLAGS += -DNDEBUG -s -static
release: $(BIN)

$(BIN): $(OBJS)
	$(CXX) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.cpp $(DEPS)
	$(CXX) $(CPPFLAGS) -c $< -o $@

clean:
	@rm $(BIN) *.o

g++ -std=c++11 -Wall $@ -fPIC -Wl,-z,relro,-z,now \
    src/main.cpp -o awaho \
    -lboost_system -lboost_iostreams -lboost_filesystem -lboost_program_options -lboost_regex -lboost_thread -lboost_chrono \
    -lpthread

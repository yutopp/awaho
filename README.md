# Sandbox environment
**!! under construction !!**  
Currently, this program may harm your computer. Please be careful...

### Ex

```
sudo awaho --mount /tmp/test_home:/home/torigoya --start-guest-path /home/torigoya --cputime 10 -- /bin/ls -la
```

## Requirement
- boost >= 1.56
- g++ >= 4.8.0

### How to Build(on Ubuntu 14.04)
```
sudo apt-get install g++ libbz2-dev
wget -O boost_1_58_0.tar.gz http://sourceforge.net/projects/boost/files/boost/1.58.0/boost_1_58_0.tar.gz/download
tar xzvf boost_1_58_0.tar.gz
cd boost_1_58_0
./bootstrap.sh
sudo ./b2 --with-system --with-iostreams --with-filesystem --with-program_options --with-regex -j 4 cxxflags="-std=c++11" link=static,shared install
cd ../
./build.sh -static -s -DNDEBUG
```

## License
This program is licensed under [The Boost License](http://www.boost.org/users/license.html) if not specified in files.

This program uses [Boost C++ Libraries](http://www.boost.org/) which is licensed under [The Boost License](http://www.boost.org/users/license.html)  
This program uses [picojson](https://github.com/kazuho/picojson) which is licensed under [2-clause BSD license](http://opensource.org/licenses/BSD-2-Clause)

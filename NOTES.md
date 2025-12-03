
### Building Yara library

Shared build:
```aiignore
./bootstrap.sh
./configure
make
```

Static build:
```aiignore
./bootstrap.sh
./configure --enable-static --disable-shared
make
```
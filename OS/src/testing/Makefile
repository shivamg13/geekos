CFLAGS:=$(CFLAGS) -I../../include -Wall -O0 -Wshadow -Wwrite-strings -Wuninitialized -g -DGEEKOS -DREDEFINE_KASSERT

all: ../../build/tools/dump-image

image-builder: image-builder.o  fake-blockdev.o bitset.o
	$(CC) $(CFLAGS) $^ -o $@

../../build/tools/dump-image: dump-image.o fake-blockdev.o bitset.o gfs2.o bufcache.o
	$(CC) $(CFLAGS) $^ -o $@

./di: dump-image.o fake-blockdev.o bitset.o gfs2.o bufcache.o
	$(CC) $(CFLAGS) $^ -o $@

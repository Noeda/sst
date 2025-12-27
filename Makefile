.PHONY: release debug build clean

CC := cc
EXECUTABLE := sst
SRC := sst.c
CFLAGS := -Wall -Wextra \
	  -fstack-protector-strong \
	  -fPIE -pie \
	  -static \
	  -Wl,-z,relro,-z,now

release: CFLAGS += -O2
release: build

debug: CFLAGS += -Og -g
debug: build

build:
	$(CC) $(CFLAGS) -o $(EXECUTABLE) $(SRC)

clean:
	rm -f $(EXECUTABLE)

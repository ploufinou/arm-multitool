ARCH=arm-unknown-linux-gnueabi-
#ARCH=
CC=$(ARCH)gcc
CC=$(ARCH)gcc
AS=$(ARCH)as
STRIP=$(ARCH)strip

LDFLAGS=-nostdlib -static -Wl,--gc-sections
CFLAGS=-nostdlib -Os -mthumb -Wall -ffunction-sections -fdata-sections 

EXECS = arm-multitool

all: $(EXECS)
	$(STRIP) $(EXECS)

syscall.o: syscall.s

arm-multitool.o: arm-multitool.c common.h

arm-multitool: arm-multitool.o common.o syscall.o

clean:
	rm -f *.o arm-multitool *~

.PHONY: all clean

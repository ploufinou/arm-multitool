ARCH=arm-linux-gnueabi-
#ARCH=
CC=$(ARCH)gcc
CC=$(ARCH)gcc
AS=$(ARCH)as
STRIP=$(ARCH)strip

LDFLAGS=-nostdlib -static -Wl,--gc-sections -z noexecstack
CFLAGS=-nostdlib -Os -Wall -mthumb -ffunction-sections -fdata-sections -ffreestanding

EXECS = arm-multitool

all: $(EXECS)
	$(STRIP) $(EXECS)

syscall.o: syscall.s

arm-multitool.o: arm-multitool.c common.h

arm-multitool: arm-multitool.o common.o syscall.o

clean:
	rm -f *.o arm-multitool *~

.PHONY: all clean

CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I./include

LDADD += -lteec -L$(TEEC_EXPORT)/lib 


.PHONY: all
all: register producer consumer unregister

register: register_device.o
	$(CC) $(LDADD) -o $@ $<

producer: producer.o
	$(CC) $(LDADD) -o $@ $< 

consumer: consumer.o
	$(CC) $(LDADD) -o $@ $< 

unregister: unregister_device.o
	$(CC) $(LDADD) -o $@ $< 

.PHONY: clean
clean:
	rm -f consumer consumer.o 
	rm -f producer producer.o
	rm -f register register_device.o
	rm -f unregister unregister_device.o

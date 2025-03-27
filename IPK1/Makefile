CC = gcc
CFLAGS = -std=gnu17 -Wall -O2
LIBS = -lpcap -lpthread

# Složka se zdrojáky
SRCDIR = src

SRCS = $(SRCDIR)/main.c \
       $(SRCDIR)/utils.c \
       $(SRCDIR)/interfaces.c \
       $(SRCDIR)/scan_tcp.c \
       $(SRCDIR)/scan_udp.c

OBJS = $(SRCS:.c=.o)

TARGET = ipk-l4-scan

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

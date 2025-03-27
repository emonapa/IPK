CC = gcc
CFLAGS = -std=gnu17 -Wall -O2
LIBS = -lpcap -lpthread

SRCS = main.c utils.c interfaces.c scan_tcp.c scan_udp.c
OBJS = $(SRCS:.c=.o)

TARGET = ipk-l4-scan

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

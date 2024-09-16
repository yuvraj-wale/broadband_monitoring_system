# CC = gcc
# CFLAGS = -Wall -Wextra -O2
# LDFLAGS = -lpcap -lmaxminddb ../../nDPI/src/lib/libndpi.a -lm

# INCLUDES = -Iinclude -I../../nDPI/src/include
# SRCS = src/main.c src/capture.c src/parser.c src/classifier.c lib/hashtable.c
# OBJS = $(SRCS:.c=.o)
# EXEC = ip-link-analyzer

# all: $(EXEC)

# $(EXEC): $(OBJS)
# 	$(CC) $(CFLAGS) $(OBJS) -o $(EXEC) $(LDFLAGS)

# %.o: %.c
# 	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# clean:
# 	rm -f $(OBJS) $(EXEC)

# .PHONY: all clean

CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -shared -lpcap -lmaxminddb -lm

INCLUDES = -Iinclude
SRCS = src/main.c src/capture.c src/parser.c src/classifier.c lib/hashtable.c
OBJS = $(SRCS:.c=.o)
LIB = libip_link_analyzer.so

all: $(LIB)

$(LIB): $(OBJS)
	$(CC) $(OBJS) -o $(LIB) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB)

.PHONY: all clean


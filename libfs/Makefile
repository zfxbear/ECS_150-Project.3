# Target library
lib := libfs.a

all: $(lib)

## TODO: Phase 1
CC	:= gcc
CFLAGS	:= -Wall -Wextra -Werror

OBJS := disk.o fs.o

$(lib): $(OBJS)
	ar -rc $(lib) $^

fs.o: fs.c
	$(CC) $(CFLAGS) -c -g -o $@ $<

disk.o: disk.c
	$(CC) $(CFLAGS) -c -g -o $@ $<

clean:
	rm $(OBJS) $(lib)
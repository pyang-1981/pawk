CPPFLAG = -ggdb -I /home/pyang/Src/gawk-4.1.3
LDFLAG = -L /usr/local/lib -l dl -l pthread -l gtest
CC =  g++
CPP_SRC = test_escape.cc
CPP_OBJS = $(CPP_SRC:.cc=.o)
C_OBJS = $(wildcard ../../*.o)


all: test

test: $(CPP_OBJS) $(C_OBJS)
	$(CC) -o test $(CPP_OBJS) $(C_OBJS) $(LDFLAG)

$(CPP_OBJS): %.o: %.cc
	$(CC) -c -o $@ $(CPPFLAG) $< && echo $(C_OBJS)




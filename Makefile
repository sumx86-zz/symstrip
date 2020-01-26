CC=g++
FLAGS=-Wall -std=c++11
ODIR=obj

objs:
	@if [ ! -d $(ODIR) ]; then\
		mkdir $(ODIR);\
	fi

	$(CC) $(FLAGS) -c symstrip.cpp -o $(ODIR)/symstrip.o
	$(CC) $(FLAGS) -c itoa.c -o $(ODIR)/itoa.o

all:
	make objs;
	$(CC) $(FLAGS) $(ODIR)/symstrip.o $(ODIR)/itoa.o -o symstrip

clean:
	rm -f $(ODIR)/*.o

.PHONY: objs, clean, all

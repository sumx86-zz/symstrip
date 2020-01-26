CC=g++
FLAGS=-Wall -std=c++11
ODIR=obj

obj:
	@if [ ! -d $(ODIR) ]; then\
		mkdir $(ODIR);\
	fi

	$(CC) $(FLAGS) -c symstrip.cpp -o $(ODIR)/symstrip.o
	$(CC) $(FLAGS) -c itoa.c -o $(ODIR)/itoa.o

all:
	make obj;
	$(CC) $(FLAGS) $(ODIR)/symstrip.o $(ODIR)/itoa.o -o symstrip

clean:
	rm -f $(ODIR)/*.o

.PHONY: obj, clean, all
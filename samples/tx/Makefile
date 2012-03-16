LIBS = -lpthread -lps -lnuma
LIB_DIR = -L../../lib

.PHONY: clean

all: tx 

tx: tx.c pkt_buff.c
	gcc  -O0 -g -Wall -o rep_trace tx.c pkt_buff.c $(LIB_DIR) $(LIBS)

clean:
	rm -f tx 

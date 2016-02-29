MODULE=event_listener
LIBRARY=pusherClib

CJSON_DIR = ./cJSON
WEBSOCKETS_DIR = ./libwebsockets
OPENSSL_DIR = /usr/local/Cellar/openssl/1.0.2d_1
AR=ar
RANLIB=ranlib
MKDIR=mkdir
MV=mv

SRC = pusher.c     \
      $(CJSON_DIR)/cJSON.c \
      utf8.c \
      queue.c

INC = -I$(CJSON_DIR) -I$(WEBSOCKETS_DIR)/lib -I$(WEBSOCKETS_DIR)/build \
      -I$(OPENSSL_DIR)/include -I./sglib

LIBS = -L$(OPENSSL_DIR)/lib -L$(WEBSOCKETS_DIR)/build/lib  -L./ -L./lib -lwebsockets -lssl -lcrypto -lz -lcurl \
        -lpthread -lm

OBJS = $(SRC:.c=.o)

CFLAGS = $(INC) -Wall -g -Wno-unused-variable -Wno-unused-function -Wno-unused-label \
         -Wno-deprecated-declarations

all: libws $(OBJS)
	$(AR) -rv lib$(LIBRARY).a $(OBJS)
	$(MKDIR) -p lib
	$(MV) lib$(LIBRARY).a lib

libws:
	if ! [ -d "libwebsockets/build" ]; then \
	  $(MKDIR) -p libwebsockets/build; \
	  cd libwebsockets/build; cmake -DLWS_WITH_SHARED=OFF -DLWS_WITHOUT_SERVER=ON ..; \
	fi
	make -C libwebsockets/build

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

test: $(OBJS) test.o
	$(CC) $(CFLAGS) $(LIBS) $(OBJS) $(LIBS) test.o -o test

clean:
	rm -f *.o
	rm -f $(MODULE)
	rm -f test
	rm -f lib/*.a

distclean:
	rm -rf libwebsockets/build

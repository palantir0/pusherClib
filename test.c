#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cJSON.h"
#include "libwebsockets.h"
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include "openssl/hmac.h"
#include "openssl/sha.h"
#include <curl/curl.h>
#include "utf8.h"
#include "sglib.h"
#include "queue.h"
#if 1
#include "config.h"
#else
#include "local_config.h"
#endif

#include "pusher.h"


    /// Define as 1 or 0 if plain text
#define PUSHER_USE_SSL 0

char *
getUserId() {
    return DEFAULT_PUSHER_CHANNEL;
}

/// ----------   Pusher event handlers -----------------------------


    /// Callback to handle connection established.
void 
connectionEstablishedHandler(struct PusherConnection *conn,
                             cJSON *data) {
    cJSON *socketItem = cJSON_GetObjectItem(data, "socket_id");
    if (socketItem != NULL && socketItem->valuestring != NULL) {
        char *socketId = strdup(socketItem->valuestring);
        printf("Pusher connection established, id=%s\n", socketId);
        conn->socketId = socketId;
        subscribe(conn, getUserId(), NULL, 0);
    }
}

void 
allEventHandler(struct PusherConnection *conn, cJSON *data) {
    if (data != NULL) {
        printf("rx event: %s\n", cJSON_Print(data));
    }
}

struct event eventHandlers[] = {
    { "pusher:connection_established", connectionEstablishedHandler },
    { "*", allEventHandler },
    { NULL, NULL }
};

int forceExit = 0;
    // Catch exit request
void sighandler(int sig)
{
	forceExit = 1;
}

int wasClosed = 0;

int main(int argc, char *argv[]) {
    int n = 0;
    int rc =0;
	signal(SIGINT, sighandler);
	int port = PUSHER_USE_SSL==1 ? 443 : 80;
	char *address = PUSHER_USE_SSL==1 ? "wss.pusherapp.com" : "ws.pusherapp.com";

    // #### WARNING ### --> Make sure to modify config.h with your key
    struct PusherConnection *conn = pusherCreate(PUSHER_KEY, NULL);

    conn->eventHandlers = eventHandlers;
    rc = makeConnection(address, port, PUSHER_USE_SSL, conn);
    if (rc < 0)
        return rc;

    pusherStart(conn);

    int i= 0;
    n = 0;
    while (!forceExit && !conn->closed) {
        sleep(1);
    }
    rc = 0;

done:
	fprintf(stderr, "Exiting: %d\n", rc);
    pusherDestroy(conn);
    return rc;
}

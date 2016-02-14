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
#include <pthread.h>
#include "pusher.h"


//this should be define somewhere
#define CLIENT_NAME "pusher-cLib"
#define CLIENT_VERSION "0.1"
#define PUSHER_PROTO_VER 7
#define PUSHER_USE_SSL 1

static int
pusherListener(struct lws *wsi,
			   enum lws_callback_reasons reason,
			   void *user, void *in, size_t len);

int deny_deflate = 0;
int deny_mux = 0;


//enum PusherState pusherState = STATE_OFF;
//static struct PusherConnection *connections[10];

static char *socketId;
struct code {
    int code;
    char *desc;
};

static struct code codeMap[] = {
	{ LWS_CALLBACK_ESTABLISHED, "Established" },
	{ LWS_CALLBACK_CLIENT_CONNECTION_ERROR, "Client connect error" },
	{ LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH, "Filter pre-establish" },
	{ LWS_CALLBACK_CLIENT_ESTABLISHED, "client established" },
	{ LWS_CALLBACK_CLOSED, "Closed" },
	{ LWS_CALLBACK_CLOSED_HTTP, "Closed http" },
	{ LWS_CALLBACK_RECEIVE, "Receive" },
	{ LWS_CALLBACK_CLIENT_RECEIVE, "Client receive" },
	{ LWS_CALLBACK_CLIENT_RECEIVE_PONG, "Client receive pong" },
	{ LWS_CALLBACK_CLIENT_WRITEABLE, "Client writable" },
	{ LWS_CALLBACK_SERVER_WRITEABLE, "Server writable" },
	{ LWS_CALLBACK_HTTP, "HTTP" },
	{ LWS_CALLBACK_HTTP_BODY, "HTTP body" },
	{ LWS_CALLBACK_HTTP_BODY_COMPLETION, "HTTP body completion" },
	{ LWS_CALLBACK_HTTP_FILE_COMPLETION, "HTTP file completion" },
	{ LWS_CALLBACK_HTTP_WRITEABLE, "HTTP writable" },
	{ LWS_CALLBACK_FILTER_NETWORK_CONNECTION, "Filter network connection" },
	{ LWS_CALLBACK_FILTER_HTTP_CONNECTION, "Filter HTTP connection" },
	{ LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED, "Server new client instantiated" },
	{ LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION, "Filter protocol connection" },
	{ LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS, "Openssl load extra client verify certs" },
	{ LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS, "Openssl load extra server verify certs" },
	{ LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION, "Openssl perform client cert verification" },
	{ LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER, "Client append handshake header" },
	{ LWS_CALLBACK_CONFIRM_EXTENSION_OKAY, "Confirm extension okay" },
	{ LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED, "Client confirm extension support" },
	{ LWS_CALLBACK_PROTOCOL_INIT, "Protocol init" },
	{ LWS_CALLBACK_PROTOCOL_DESTROY, "Protocol destroy" },
	{ LWS_CALLBACK_WSI_CREATE, "Wsi create" }, /* always protocol[0] */
	{ LWS_CALLBACK_WSI_DESTROY, "Wsi destroy" }, /* always protocol[0] */
	{ LWS_CALLBACK_GET_THREAD_ID, "Get thread id" },

	/* external poll() management support */
	{ LWS_CALLBACK_ADD_POLL_FD, "Add poll fd" },
	{ LWS_CALLBACK_DEL_POLL_FD, "Del poll fd" },
	{ LWS_CALLBACK_CHANGE_MODE_POLL_FD, "Change mode poll fd" },
	{ LWS_CALLBACK_LOCK_POLL, "Lock poll" },
	{ LWS_CALLBACK_UNLOCK_POLL, "Unlock poll" },

	{ LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY, "Openssl context requires private key" }

    };


    ///
    /// Create a unique channel ID for application.
    /// @param conn A connection instance with valid libwebsocket context
    /// @return A malloc'd string that must be freed by caller
    ///
char *createChannelId(struct lws_context *context, const char *channelPrefix) {
    char    hash[8];
    char    key[32];
	int 	i;

        // Use our websocket library for randomness
	int rc = lws_get_random(context, hash, 8);
        // we asked for 6 bytes, make sure it is 6
	if (rc != 6) {
        printf("Unable to read random, use rand\n");
            // default to simple rand()
        for (i=0; i<sizeof(hash); i++) {
            hash[i] = rand();
        }
	}

    memset(key, 0, sizeof(key));
    strcpy(key, channelPrefix);
    snprintf((char *)&key[strlen(key)], sizeof(key)-strlen(key)-1, "%ld", *(unsigned long *)hash);
    
    return strdup(key);
}

cJSON *jsonEvent(cJSON *root, char *eventName, char *eventData, 
                 const char **channels, int noofChannels, char *channel, char *socketId) {

    cJSON_AddStringToObject(root, "event", eventName);
    cJSON_AddStringToObject(root, "data", eventData);

    cJSON *jsonChannels = cJSON_CreateStringArray(channels, noofChannels);
    cJSON_AddItemToObject(root, "channels", jsonChannels);
    cJSON_AddStringToObject(root, "channel", channel);
    if (socketId != NULL)
        cJSON_AddStringToObject(root, "socket_id", socketId);

    return root;
}

    /// Assemble a Pusher event json object.  Note, pusher: prefixed
    /// events are straight json encoded whereas other types of events
    /// use the serialized json string as the data parameter.
cJSON *websockEvent(cJSON *root, char *eventName, cJSON *eventData) {
    cJSON_AddStringToObject(root, "event", eventName);
        // some events do not have data so send null json
    if (eventData == NULL)
        cJSON_AddStringToObject(root, "data", "{}");
    else {
        if (strncmp("pusher:", eventName, 7) == 0) {
            cJSON_AddItemToObject(root, "data", eventData);
        } else {
            char *s = cJSON_PrintUnformatted(eventData);
            cJSON_AddStringToObject(root, "data", s);
        }
    }
    return root;
}


    /// Create an HMAC SHA256 hash for the given str
    /// @param str String to create hash on
    /// @param key Secret to use for hash
    /// @param digest buffer to hold key, no longer than SHA256_DIGEST_LENGTH+1.  It will come
    /// back as a 0 terminated c-string.
int generateHash(char *str, char *key, char digest[(SHA256_DIGEST_LENGTH*2)+1]) {
	int i;
    unsigned char *result =    
        HMAC(EVP_sha256(), (unsigned char *)key, strlen(key), (unsigned char *)str, strlen(str), NULL, NULL);
    if (result == NULL)
        return -1;

    for (i=0; i<SHA256_DIGEST_LENGTH; i++) {
        sprintf(&digest[i*2], "%02x", *result++);
    }
    digest[SHA256_DIGEST_LENGTH*2] = '\0';
    printf("Hash = %s\n", digest);
    return 0;
}

    /// Create a manual ping event and queue it to be sent.
int queuePing(struct PusherConnection *conn) {
    struct MessageEntry *msg = (struct MessageEntry *)malloc(sizeof(struct MessageEntry));
    if (msg == NULL)
        return -ENOMEM;

    sprintf((char *)msg->event, "%s", "pusher:ping");
    msg->data = NULL;

    printf("queue ping: %s\n", (char *)msg->event);

    int rc = sgEnqueue(conn->msgQueue, (void *)msg);
    return rc;
}


    /// Send an event on the websocket.  Keep in mind that the websocket
    /// must be in a send state in order to do this.  So during the time of 
    /// the lws callback, this can be used to send an event.
    /// @param wsi the socket to send
    /// @param event the name of the event. (e.g. "pusher:subscribe")
    /// @param data the inforamtion that should be put as a string in the 'data'
    /// field.  However, if the event has the 'pusher:' prefix, this data will be 
    /// sent as a json object rather than serialized.
    /// @return neg on failure, 1 or greater for success, 0 means no data was sent.
int sendEvent(struct lws *wsi, char *event, cJSON *data) {
    char    pusherEventBuf[512];
        // Get main json object
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        printf("Out of memory\n");
			// Deleting root has a side-effect of deleting 'data' so delete this 
			// before returning so the function is consistent otherwise caller will
			// need to figure out what to do on return.
		cJSON_Delete(data);
        return -ENOMEM;
    }

        // add portions to root
    websockEvent(root, event, data);
        // get a serialized version of the json
    char *json = cJSON_PrintUnformatted(root);
    if (json == NULL) {
        printf("Invalid json\n");
		cJSON_Delete(root);
        return -1;
    }

        // Create a buffer with some extra padding since data must be sent before and after the 
        // string to make it websockified.
    int buflen = LWS_SEND_BUFFER_PRE_PADDING + LWS_SEND_BUFFER_POST_PADDING + strlen(json)+1;
    unsigned char *buf = (unsigned char *)malloc(buflen);
    if (buf == NULL) {
        cJSON_Delete(root);
        printf("Out of memory\n");
        return -ENOMEM;
    }
    snprintf((char *)&buf[LWS_SEND_BUFFER_PRE_PADDING], buflen, "%s", json);
    printf("sending event: %s\n", json);

	// NOTE: all the bytes need not be sent, so this would queue a write callback
	// and the rest would then need to be sent.  TODO currently this is not handled
    int n = lws_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], 
                               strlen(json), LWS_WRITE_TEXT);
		// cleanup
    cJSON_Delete(root);
    free(buf);
    printf("Write %d bytes\n", n);
    return n;
}


    /// Create a json "auth" object 
char *getAuth(struct PusherConnection *conn, char *str) {
    if (conn->socketId == NULL) {
        printf("Invalid socket id\n");
        return NULL;
    }
    if (conn->apiSecret == NULL) {
        printf("API secret not set\n");
        return NULL;
    }
    unsigned char digest[(SHA256_DIGEST_LENGTH*2)+1];
    if (generateHash(str, conn->apiSecret, (char *)digest) < 0
        || strlen((char *)digest) != 64) {
        printf("digest length error: %d\n", (int)strlen((const char *)digest));
        return NULL;
    }

        // hash + : + socketId str + 0-term
    int sigSz = (SHA256_DIGEST_LENGTH*32)+1+(strlen(conn->socketId))+1;
    char *sig = (char *)malloc(sigSz);
    snprintf(sig, sigSz , "%s:%s", conn->apiKey, (char *)digest);

    return sig;
}

    /// Subscribe to a channel without any fancy authorization
int subscribe(struct PusherConnection *conn, char *channel, char *events[], int useAuth) {
    int rc = 0; 

        // The container for populating the "data" string
    cJSON *sub = cJSON_CreateObject();

        // build json string that will be serialized then added to data
    cJSON_AddStringToObject(sub, "channel", channel);
    if (useAuth) {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s:%s", conn->socketId, channel);
        buf[sizeof(buf)-1] = '\0';
        char *authSignature = getAuth(conn, buf);
        if (authSignature == NULL) {
            cJSON_Delete(sub);
            return -1;
        }
        printf("authSig = %s\n", authSignature);
        cJSON_AddStringToObject(sub, "auth", authSignature);
		free(authSignature);
    }

        // Create message to queue
    struct MessageEntry *msg = (struct MessageEntry *)calloc(1, sizeof(struct MessageEntry));
    if (msg == NULL) {
        return -1;
    }
    
        // populate msg
    snprintf(msg->event, sizeof(msg->event), "%s", "pusher:subscribe");
    msg->event[sizeof(msg->event)-1] = '\0';
    msg->data = sub;
    
        // make it so - this will be dequeued by the callback
    rc = sgEnqueue(conn->msgQueue, (void *)msg);
        // this kicks the websocket to make sure there is a callback to write the next event.
    lws_callback_on_writable(conn->websock);

    return rc;
}

    /// Find the correct event handler for the event sent from the server.
static void
processEvent(char *event, cJSON *data, struct PusherConnection *conn) {
	int i;
    if (conn->eventHandlers == NULL)
        return;

    for (i=0; conn->eventHandlers[i].name != NULL; i++) {
        if (strcmp(conn->eventHandlers[i].name, "*") && strcmp(event, conn->eventHandlers[i].name))
            continue;

        printf("Processing event: %s\n", conn->eventHandlers[i].name);
        conn->eventHandlers[i].handler(conn, data);
        break;
    }
}

    // Listener for all things websocket/Pusher.
static int
pusherListener(struct lws *wsi,
			   enum lws_callback_reasons reason,
               void *user, void *in, size_t len)
{
    char *decodedReason = "Unknown";
    if (reason < (sizeof(codeMap)/sizeof(struct code))) {
        decodedReason = codeMap[reason].desc;
    }

    printf("pusherListener: %d: %s\n", reason, decodedReason);
    //if (in != NULL && len > 0) {
    //    printf("rx len=");
    //    ((char *)in)[len-1] = '\0';
    //    printf("%d '%s'\n", (int)len, (char *)in);
   // }
    struct PusherConnection *conn = NULL;
    if (wsi != NULL && lws_get_protocol(wsi) != NULL)
        conn = (struct PusherConnection *)lws_get_protocol(wsi)->user;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		printf("pusherListener: LWS_CALLBACK_CLIENT_ESTABLISHED\n");
        lws_callback_on_writable(wsi);
        if (conn != NULL)
            conn->connected = 1;

		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		printf("LWS_CALLBACK_CLIENT_CONNECTION_ERROR\n");
        if (conn != NULL) {
            conn->closed = 1;
            conn->connected = 0;
        }
		break;

	case LWS_CALLBACK_CLOSED:
		printf("LWS_CALLBACK_CLOSED\n");
        if (conn != NULL) {
            conn->closed = 1;
            conn->connected = 0;
        }
		break;

	case LWS_CALLBACK_RECEIVE:
	case LWS_CALLBACK_CLIENT_RECEIVE:
        if (in != NULL && len > 0) {
            ((char *)in)[len] = '\0';
            printf("rx len %d '%s'\n", (int)len, (char *)in);
            cJSON *json = cJSON_Parse(in);
            if (json == NULL) 
                break;
            cJSON *itemEvent = cJSON_GetObjectItem(json, "event");
            cJSON *itemData = cJSON_GetObjectItem(json, "data");

            if (itemEvent == NULL || itemData == NULL) {
				cJSON_Delete(json);
                break;
			}
            char *event = itemEvent->valuestring;
            char *dataStr = itemData->valuestring;
            if (event == NULL || dataStr == NULL) {
				cJSON_Delete(json);
                break;
           	} 
            cJSON *data = cJSON_Parse(dataStr);
            if (data == NULL)  {
				cJSON_Delete(json);
                break;
			}
                // We have an event and the data json so lets process it
            processEvent(event, data, (struct PusherConnection *)lws_get_protocol(wsi)->user);

                // cleanup
            cJSON_Delete(data);
            cJSON_Delete(json);
        }
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
	case LWS_CALLBACK_SERVER_WRITEABLE:
        {
            printf("WRITEABLE callback\n");
            int rc = 0;
            struct PusherConnection *conn = (struct PusherConnection *)lws_get_protocol(wsi)->user;
            if (conn != NULL && conn->msgQueue != NULL) {
                printf("dequeue msg\n");
                struct MessageEntry *entry;
                rc = sgDequeue(conn->msgQueue, (void *)&entry);
                printf("msg: %d\n", rc);
                if (!rc && entry != NULL) {
                    printf("sendEvent\n");
						// entry->data is freed on this call
                    rc = sendEvent(wsi, entry->event, (entry->data != NULL ? entry->data : NULL));
					if (rc < 0) {
						printf("sendEvent Failed\n");
					} else {
						printf("Event sent, queue up next write event\n");
						lws_callback_on_writable(wsi);
					}
					free(entry);
                } else {
                    printf("Unable to dequeue event\n");
                }
            } else {
                if (conn == NULL)
                    printf("!! Can't find connection. !!\n");
                else
                    printf("!! No message queue available !!\n");
            }
        }
		break;


	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
		if ((strcmp(in, "deflate-stream") == 0) && deny_deflate) {
			printf("denied deflate-stream extension\n");
			return 1;
		}
		if ((strcmp(in, "deflate-frame") == 0) && deny_deflate) {
			printf("denied deflate-frame extension\n");
			return 1;
		}
		if ((strcmp(in, "x-google-mux") == 0) && deny_mux) {
			printf("denied x-google-mux extension\n");
			return 1;
		}

		break;

	default:
		break;
	}

	return 0;
}

    /// Cleanup protocol
void closeAndFreeConnection(struct PusherConnection *conn) {
	int i;
    printf("closeAndFreeConnection\n");
    if (conn->context != NULL)
        lws_context_destroy(conn->context);

    if (conn->msgQueue != NULL) {
        struct MessageEntry *entry;
        printf("free msgQueue\n");
        while(sgDequeue(conn->msgQueue, (void *)&entry) > 0) {
            if (entry && entry->data)
                cJSON_Delete(entry->data);
			
			if (entry)
				free(entry);
        }
    }
    printf("free protocols\n");
    if (conn->info.protocols != NULL) {
        free((char *)conn->info.protocols);
		conn->info.protocols = NULL;
    }
    printf("free connection\n");
    free(conn);
}

/* list of supported protocols and callbacks for Pusher*/
/* These are the default and structure should not be used directly */
static struct lws_protocols defProtocols[] = {
	{
#if (PUSHER_USE_SSL==1)
		"ws",  // protocol name
#else
		"ws",
#endif
		pusherListener, // callback for protocol
		0,
		1536, // max size of payload
        1,
        NULL
	},
	{ NULL, NULL, 0, 0 } /* end */
};

void logOut(int level, const char *line) {
    fprintf(stderr, "%s\n", line);
}

    /// Helper to create a connection with Pusher.  This will allocate a Connection structure,
    /// init websocket and connect with Pusher.  After that, the caller is responsible
    /// for putting the thread to manage the service.  The returned Connection is not 
    /// truly available as it just kicks off the process.  
    ///
    /// @param address The host_domain address string to connect with.
    /// @param port    The port ot use
    /// @param use_ssl Whether to use SSL or leave unencrypted.  That said, clients mask the
    /// @param protocols How to handle specific protocols
    /// @param conn A Pusher connection instance that is needed for all communication with the library
    /// data so sent data is not easy to see.
int
makeConnection(char *address, int port, int use_ssl, struct PusherConnection *conn) {
	int n = 0;
	int ret = 0;
    struct lws_protocols *protocols = 
        (struct lws_protocols *)calloc(2, sizeof(struct lws_protocols));
    memcpy((char *)protocols, (char *)defProtocols, sizeof(defProtocols));

        // this gets passed around in the callback
    protocols[0].user = conn;
	conn->info.protocols = protocols;
    conn->use_ssl = use_ssl;
	conn->port = port;
	conn->address = address;

    lws_set_log_level(~0, logOut);
    struct lws_context *context = lws_create_context(&conn->info);
    if (context == NULL) {
        fprintf(stderr, "Creating lws context failed\n");
		conn->info.protocols = NULL;
        free(protocols);
        return -1;
    }

        // Setup the GET path that is sent to Pusher to convert this to the websocket protocol.
        // Note, the protocol version is a Pusher version and not the ietf websocket protocol #.
    char webpath[512];
    snprintf(webpath, sizeof(webpath), "/app/%s?client=%s-linux-CLib&protocol=%d&version=%s", 
             conn->apiKey, CLIENT_NAME, PUSHER_PROTO_VER, CLIENT_VERSION);
    webpath[sizeof(webpath)-1] = '\0';
    printf("using path: %s\n", webpath);

    char addrPort[200];
    snprintf(addrPort, sizeof(addrPort), "%s:%u", address, port);
    printf("using address: %s\n", addrPort);
    conn->context = context;

        // Setting up a client connection.  This just starts the process.  The 
        // lws_service() is what managed the connections and initial 
        // handshake.  The connection you get back is only for reference and only 
        // during the callback should data be sent.
	conn->websock = lws_client_connect(
                            conn->context, 
                            conn->address,  // just host
                            conn->port,   
                            (conn->use_ssl ? 2 : 0),      // 0 for plain, 2 for ssl
			                webpath,   // HTTP GET $s portion
                            addrPort,  // should be host:port
                            NULL, // not used as far as I know
                            (conn->use_ssl ? "ws" : "ws"),// to ssl or not
                            -1
                            ); // pass -1, 13 is the current version and is required
                                 // also, it has nothing to do with Pusher version/protocol

	if (conn->websock == NULL) {
		fprintf(stderr, "lws connect failed: %d\n", errno);
		ret = 1;
		goto done;
	}

    return 0;

done:
        // if the protocol doesn't setup correctly then cleanup
	fprintf(stderr, "makeConnection failed: %d\n", ret);
    lws_context_destroy(conn->context);
	conn->info.protocols = NULL;
	conn->context = NULL;
    free(protocols);
	return -1;
}

int
pusherService(struct PusherConnection *conn, long timeoutInMillis) {
    return lws_service(conn->context, 5000);
}


void *websockProcessing(void *arguments) {
    int n = 0;
	int i;
    int closed = 0;
    struct PusherConnection *conn = (struct PusherConnection *)arguments;
    
    sem_wait(&conn->lock);
    conn->pusherState = STATE_RUNNING;
    sem_post(&conn->lock);
    while (!conn->terminate) {
        if (!conn->closed && conn->context != NULL && conn->websock != NULL) {
            n = lws_service(conn->context, 10000);
            if (n < 0) {
				fprintf(stderr, "connection died attempting to service it\n");
					// connection died, turn off servicing
                conn->closed = 1;
                free((char *)conn->info.protocols);
                conn->info.protocols = NULL;
                lws_context_destroy(conn->context);
                conn->context = NULL;
				conn->pusherState = STATE_TERM;
            } else
                continue;
        }
        if (conn->terminate)
            break;
        sleep(2);
    }
    conn->closed = 1;
    sem_wait(&conn->lock);
    conn->pusherState = STATE_TERM;
    sem_post(&conn->lock);
    pthread_exit(NULL);
}


struct PusherConnection *
pusherCreate(char *apiKey, cJSON *options) {
    struct PusherConnection *conn = (struct PusherConnection *)calloc(1, sizeof(struct PusherConnection));

    if (conn == NULL) {
        printf("Unable to alloc memory for Pusher connection!\n");
        return NULL;
    }

    sem_init(&conn->lock, 1, 1);
	conn->info.port = CONTEXT_PORT_NO_LISTEN;
#ifndef LWS_NO_EXTENSIONS
	conn->info.extensions = lws_get_internal_extensions();
#endif
	conn->info.gid = -1;
	conn->info.uid = -1;
    conn->info.ka_time=120;
    conn->info.ka_interval=25;
    conn->info.ka_probes=6;
    conn->pusherOptions = options;
    conn->apiKey = apiKey;

    conn->msgQueue = sgCreateQueue(20);
    if (conn->msgQueue == NULL) {
        printf("Message queue create failed!\n");
    }

    return conn;
}

void
pusherStart(struct PusherConnection *conn) {
    sem_wait(&conn->lock);
    if (conn->pusherState == STATE_OFF) {
        pthread_create(&conn->websockServiceThread, NULL, websockProcessing, (void *)conn);
        conn->pusherState = STATE_INIT;
    }
    sem_post(&conn->lock);
}

int
pusherInit() {
    return 0;
}

void
pusherDestroy(struct PusherConnection *conn) {
    conn->terminate = 1;
    if (conn->pusherState > STATE_OFF) {
        pthread_join(conn->websockServiceThread, NULL);
    }
    sem_wait(&conn->lock);
    conn->pusherState = STATE_OFF;
    sem_post(&conn->lock);
    closeAndFreeConnection(conn);
}

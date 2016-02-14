#ifndef __PUSHER_H__
#define __PUSHER_H__

#define API_RESULT_OK   200
#define API_ERROR       400
#define API_AUTH_ERROR  401
#define API_APP_DISABLED 403
#define MAX_EVENT_NAME_LEN  256

struct PusherConnection;
    /// Callback function for registered events
typedef void (*eventHandler)(struct PusherConnection *conn, cJSON *);
    /// event handler structure
struct event {
    char *name;  ///< Name of event or * for all events
    eventHandler handler; ///< Callback function
};

enum PusherState {
    STATE_OFF, 
    STATE_INIT, 
    STATE_RUNNING,
    STATE_TERM
    };

    /// Defines a connection instance with a Pusher server.
struct PusherConnection {
        // websock parameters used internally
    struct lws_context *context;
    struct lws_protocols *protocols;
    struct lws_context_creation_info info;
    struct lws *websock;
        
    char *address; ///< The host_domain address string to connect with.
    int port;      ///< Port of the pusher server; s/b 80 or 443
    int use_ssl;   ///< Set to 1 to use SSL
    char *socketId; ///< When connection has completed, this will be the id assigned by server
    char *apiKey;  ///< Your Pusher API key
    char *apiSecret;///< Your Puhser API secret
    struct event *eventHandlers; ///< Subscribed event handlers

    struct Queue *msgQueue; ///< Send queue - responses are always callbacks.
    char **events; ///< Array of event strings
    cJSON *pusherOptions; ///< Options to be used by pusher lib (TBD)
    volatile int closed; ///< set to 0 when structure is valid, closed if socket was closed or died.
    volatile int connected; ///< Connected to Pusher server

    void *userData; ///< Carry user info for the pusher connection used in callbacks

    pthread_t websockServiceThread;
    int  terminate;
    enum PusherState pusherState;
    sem_t lock; 
};

typedef void (*callbackFunc)(struct PusherConnection *conn, void *data);
struct MessageEntry {
    char    event[MAX_EVENT_NAME_LEN];
    cJSON  *data;
};

    /// Initialize the pusher library, must be called before any other calls
int pusherInit();
    /// After all connections have been terminated, call this to terminate connection
    /// This function may block until all threads have terminated.
void pusherDestroy(struct PusherConnection *conn);

    /// Start thread processing
void pusherStart(struct PusherConnection *conn);

    /// Create a pusher connection.  This will start the service thread for the library
    /// on the first call.
    /// @param apiKey   Your pusher API key
    /// @param options json encoded options for the pusher library, unsupported currently.
    /// @return A valid connection structure or NULL on failure.
struct PusherConnection *pusherCreate(char *apiKey, cJSON *options);
    /// Init and execute a connection to the Pusher server.  Note, this does not in itself
    /// perform the tcp connection.  On return, the connection has not been established.
    /// The calling app will get a callback when connection has been established.
int makeConnection(char *address, int port, int use_ssl, struct PusherConnection *conn);
    /// When done with a connection, call this on it.
    /// @param conn The connection to close
void closeAndFreeConnection(struct PusherConnection *conn);
    /// Subscribe to a channel.  This will establish that this pusher connection should 
    /// subscribe to a channel.  TODO: If channel is lost, it should re-subscribe automatically.
int subscribe(struct PusherConnection *conn, char *channel, char *events[], int useAuth);
    /// Manually queue up a ping to check connection.  Note, the server uses websock pings
    /// normally so this is not useful in terms of connection status.
int queuePing(struct PusherConnection *conn);
    /// Create an auth hash on the passed in str using pusher connection parameters.
    /// If the connection has not been established, this call will fail since the socketId 
    /// passed back from Pusher is required to generate the auth string.
char *getAuth(struct PusherConnection *conn, char *str);


#endif

#ifndef LCBIO_UTILS_H
#define LCBIO_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LCBIO_CSERR_BUSY, /* request pending */
    LCBIO_CSERR_INTR, /* eintr */
    LCBIO_CSERR_EINVAL, /* einval */
    LCBIO_CSERR_EFAIL, /* hard failure */
    LCBIO_CSERR_CONNECTED /* connection established */
} lcbio_CSERR;

/**
 * Convert the system errno (indicated by 'syserr')
 * @param syserr system error code
 * @return a status code simplifying the error
 */
lcbio_CSERR
lcbio_mkcserr(int syserr);

/**
 * Assigns the target error code if it indicates a 'fatal' or 'relevant' error
 * code.
 *
 * @param in Error code to inspect
 * @param[out] out target pointer
 */
void
lcbio_mksyserr(lcbio_OSERR in, lcbio_OSERR *out);

/**
 * Traverse the addrinfo structure and return a socket.
 * @param io the iotable structure used to create the socket
 * @param[in/out] ai an addrinfo structure
 * @param[out] connerr an error if a socket could not be established.
 * @return a new socket, or INVALID_SOCKET
 *
 * The ai structure should be considered as an opaque iterator. This function
 * will look at the first entry in the list and attempt to create a socket.
 * It will traverse through each entry and break when either a socket has
 * been successfully created, or no more addrinfo entries remain.
 */
lcb_socket_t
lcbio_E_ai2sock(lcbio_pTABLE io, struct addrinfo **ai, int *connerr);

lcb_sockdata_t *
lcbio_C_ai2sock(lcbio_pTABLE io, struct addrinfo **ai, int *conerr);

struct lcbio_NAMEINFO {
    char local[NI_MAXHOST + NI_MAXSERV + 2];
    char remote[NI_MAXHOST + NI_MAXSERV + 2];
};

int
lcbio_get_nameinfo(lcbio_SOCKET *sock, struct lcbio_NAMEINFO *nistrs);

void
lcbio__load_socknames(lcbio_SOCKET *sock);

#ifdef _WIN32
#define lcbio_syserrno GetLastError()
#else
#define lcbio_syserrno errno
#endif

typedef struct {
    int type;
    #define LCBIO_CONNREQ_RAW 1
    #define LCBIO_CONNREQ_POOLED 2
    #define LCBIO_CONNREQ_GENERIC 3
    union {
        struct lcbio_CONNSTART *cs;
        struct lcbio_MGRREQ *preq;
        void *p_generic;
    } u;
    void (*dtor)(void *);
} lcbio_CONNREQ;

#define LCBIO_CONNREQ_CLEAR(req) (req)->u.p_generic = NULL
#define LCBIO_CONNREQ_MKRAW(req, cs) do { \
    (req)->u.cs = cs; \
    (req)->type = LCBIO_CONNREQ_RAW; \
} while (0);
#define LCBIO_CONNREQ_MKPOOLED(req, sreq) do { \
    (req)->u.preq = sreq; \
    (req)->type = LCBIO_CONNREQ_POOLED; \
} while (0);
#define LCBIO_CONNREQ_MKGENERIC(req, p, dtorcb) do { \
    (req)->u.p_generic = p; \
    (req)->type = LCBIO_CONNREQ_GENERIC; \
    (req)->dtor = (void (*)(void *))dtorcb; \
} while (0);

void
lcbio_connreq_cancel(lcbio_CONNREQ *req);

#ifdef __cplusplus
}
#endif
#endif

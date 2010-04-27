#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>

#include <event-config.h>
#include <alloca.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/dns_struct.h>
#include <event2/util.h>

#ifdef _EVENT_HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

/* Records whose type is <= 16 are describedin RFC 1035 */
typedef enum {
    NamedHostQueryType       = 1,  // A
    NamedNameServerQueryType = 2,  // NS
    NamedCanonicalQueryType  = 5,  // CNAME
    NamedSOAQueryType        = 6,  // SOA
    NamedPointerQueryType    = 12, // PTR
    NamedMailQueryType       = 15, // MX
    NamedTxtQueryType        = 16, // TXT
    NamedQuadAQueryType      = 28, // AAAA, RFC 3596
    NamedWildcardQueryType   = 255
} NamedQueryType;

/* Other classes aren't important, see sec 3.2.4 of RFC 1035 for details */
typedef enum {
    NamedInternetQueryClass = 1,
    NamedWildcardQueryClass = 255
} NamedQueryClass;

typedef enum {
    NamedDebugLogLevel,
    NamedInfoLogLevel,
    NamedErrorLogLevel
} NamedLogLevel;

typedef void (*NamedAnswerFunc)(const char *name, const char *data, int data_len, int ttl, NamedQueryClass query_class, NamedQueryType query_type);

static void named_query_name_class_qtype(const char *name, NamedQueryClass qclass, NamedQueryType qtype, NamedAnswerFunc);
static void named_on_evdns_request(struct evdns_server_request *req, void *data);
static void named_enc_character_string(const uint8_t *in_data, int in_len, uint8_t *out_data, int *out_len, uint8_t max_chunk_size);

static const int NAMED_TTL = 300;
static sqlite3 *named_db = NULL;
static const char *NAMED_COL_DATA = "rdata";
static const char *NAMED_COL_TTL = "ttl";
static const char *NAMED_COL_QCLASS = "qclass";
static const char *NAMED_COL_QTYPE = "qtype";
static const char *NAMED_COL_NAME = "name";
static NamedLogLevel named_log_level = NamedInfoLogLevel;

#define NAMED_EV_CHECK(MSG, F) \
{ \
    if (F < 0) { \
        fprintf(stderr, "failed to " MSG); \
        exit(1); \
    } \
}

#define NAMED_LOG_DEBUG(FMT, ...) NAMED_LOG(NamedDebugLogLevel, "DEBUG", FMT, ##__VA_ARGS__)
#define NAMED_LOG_INFO(FMT, ...) NAMED_LOG(NamedInfoLogLevel, "INFO", FMT, ##__VA_ARGS__)
#define NAMED_LOG_ERROR(FMT, ...) NAMED_LOG(NamedErrorLogLevel, "ERROR", FMT, ##__VA_ARGS__)
#define NAMED_LOG(LOG_LEVEL, LEVEL_NAME, FMT, ...) { \
    if (LOG_LEVEL >= named_log_level) {\
        fprintf(stderr, "%s:%d\t%s\t" FMT "\n", __FILE__, __LINE__, LEVEL_NAME, ##__VA_ARGS__);\
    }\
}

static void named_query_name_class_qtype(const char *name, NamedQueryClass qclass, NamedQueryType qtype, NamedAnswerFunc on_answer)
{
    char *error_msg = NULL;
    char *sql;
    char *buf;
    const char *response_data = "";
    const char *response_name = "";
    const char *left;
    NamedQueryClass response_qclass = NamedInternetQueryClass;
    NamedQueryType response_qtype = 0;
    int response_ttl = NAMED_TTL;
    int response_data_len = 0;
    int rc = 0;
    int buf_size;
    sqlite3_stmt *stmt;

    NAMED_LOG_DEBUG("query: %s, class: %d, type: %d", name, qclass, qtype);

    if (qtype != NamedWildcardQueryType && qclass != NamedWildcardQueryClass)
        sql = sqlite3_mprintf("SELECT name, qtype, qclass, rdata, ttl FROM responses WHERE name = '%s' AND qclass = %d AND qtype = %d", name, (int) qclass, (int) qtype);
    else if (qtype == NamedWildcardQueryType)
        sql = sqlite3_mprintf("SELECT name, qtype, qclass, rdata, ttl FROM responses WHERE name = '%s' AND qclass = %d", name, (int) qclass);
    else if (qclass == NamedWildcardQueryClass)
        sql = sqlite3_mprintf("SELECT name, qtype, qclass, rdata, ttl FROM responses WHERE name = '%s' AND qtype = %d", name, (int) qtype);
    else
        sql = sqlite3_mprintf("SELECT name, qtype, qclass, rdata, ttl FROM responses WHERE name = '%s'", name);

    rc = sqlite3_prepare_v2(named_db, sql, -1, &stmt, &left);
    if ((rc == SQLITE_BUSY) || (rc == SQLITE_LOCKED)) {
        NAMED_LOG_ERROR("the sqlite database seems to be locked or busy");
    } else if (rc != SQLITE_OK) {
        NAMED_LOG_ERROR("unknown error while preparing sqlite statement: rc = %d", rc);
    }

    sqlite3_reset(stmt);
    while (1) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            // query is done returning results, nothing to see here
            break;
        } else if (rc == SQLITE_OK || rc == SQLITE_ROW) {
            response_name = sqlite3_column_text(stmt, 0);
            response_qtype = sqlite3_column_int(stmt, 1);
            response_qclass = sqlite3_column_int(stmt, 2);
            response_data = sqlite3_column_blob(stmt, 3);
            response_data_len = sqlite3_column_bytes(stmt, 3);
            response_ttl = sqlite3_column_int(stmt, 4);

            if (response_qtype == NamedTxtQueryType) {
                buf_size = response_data_len + (response_data_len / 255) + 16;
                buf = alloca(buf_size);
                named_enc_character_string(response_data, strlen(response_data), buf, &buf_size, 255);
                response_data = buf;
                response_data_len = buf_size;
            }
            on_answer(response_name, response_data, response_data_len, response_ttl, response_qclass, response_qtype);
        } else {
            NAMED_LOG_ERROR("unknown error in sqlite3_step: rc = %d", rc);
            exit(1);
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_free(sql);

}

static void named_enc_character_string(const uint8_t *in_data, int in_len, uint8_t *out_data, int *out_len, uint8_t max_chunk_size)
{
    int remaining = in_len;
    int written = 0;
    for (int i = 0; i < in_len && written < *out_len; i++) {
        if ((i % max_chunk_size) == 0) {
            int remaining = in_len - written;
            int chunk_size = max_chunk_size < remaining ? max_chunk_size : remaining;
            out_data[written] = (uint8_t)chunk_size;
            written++;
        }
        out_data[written] = in_data[i];
        written++;
    }
    *out_len = written;
}

static void named_on_evdns_request(struct evdns_server_request *req, void *data)
{
    int ttl = 300;
    NAMED_LOG_DEBUG("rx request");

    for (int i = 0; i < req->nquestions; i++) {
        struct evdns_server_question *question = req->questions[i];
        void on_answer(const char *name, const char *data, int data_len, int ttl, NamedQueryClass qclass, NamedQueryType qtype) {
            NAMED_LOG_DEBUG("answer name: %s, data: (%d bytes)", name, data_len);

            NAMED_EV_CHECK("add reply", evdns_server_request_add_reply(
                req,
                EVDNS_ANSWER_SECTION,
                name,
                (int)qtype,
                (int)qclass,
                ttl,
                data_len, // data len
                0,
                data));
        }
        named_query_name_class_qtype(question->name, question->dns_question_class, question->type, on_answer);
    }
    NAMED_EV_CHECK("respond", evdns_server_request_respond(req, 0));

    NAMED_LOG_DEBUG("responded");
}

static void named_logger(int is_warn, const char *msg)
{
    fprintf(stderr, "%s: %s\n", is_warn ? "WARN" : "INFO", msg);
}

static void drop_privileges(const char *pw_name)
{
    struct passwd *pwd;
    if (getuid() == 0 && strlen(pw_name)) {
        pwd = getpwnam(pw_name);
        setuid(pwd->pw_uid);
        NAMED_LOG_INFO("dropped uid to %d", pwd->pw_uid);
        if (getgid() == 0 && pwd->pw_gid)  {
            setgid(pwd->pw_gid);
            NAMED_LOG_INFO("dropped gid to %d", pwd->pw_gid);
        }
    }
}

int main(int argc, char **argv)
{
    NAMED_LOG_INFO("startup")
    struct event_base *event_base = NULL;
    struct evdns_base *evdns_base = NULL;
    struct sockaddr_in my_addr;
    int rc;
    int sock;
    int port = 10053;

    char *priv_user = calloc(1024, sizeof(char));

    int ch = -1;
    while ((ch = getopt(argc, argv, "dp:u:")) != -1) {
        switch (ch) {
        case 'd':
            named_log_level = NamedDebugLogLevel;
            break;
        case 'p':
            if (1 <= atoi(optarg) < (1 << 16))
                port = atoi(optarg);
            break;
        case 'u':
            strcpy(priv_user, optarg);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    rc = sqlite3_open(argv[0], &named_db);
    if (rc) {
        NAMED_LOG_ERROR("Can't open database: %s", sqlite3_errmsg(named_db));
        sqlite3_close(named_db);
        exit(1);
    }
    event_base = event_base_new();
    evdns_base = evdns_base_new(event_base, 0);
    evdns_set_log_fn(named_logger);

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }
    evutil_make_socket_nonblocking(sock);
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*) &my_addr, sizeof(my_addr)) < 0) {
        perror("bind");
        exit(1);
    }

    /* bind(2) is done, it's time to drop privileges */
    drop_privileges(priv_user);
    free(priv_user);

    evdns_add_server_port_with_base(event_base, sock, 0, named_on_evdns_request, NULL);

    event_base_dispatch(event_base);
    sqlite3_close(named_db);
    NAMED_LOG_INFO("done")
    return 0;
}

#undef NAMED_EV_CHECK

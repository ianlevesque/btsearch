#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <openssl/md5.h>

#include "dht.h"

#define MAX_BOOTSTRAP_NODES 500
static struct sockaddr_storage bootstrap_nodes[MAX_BOOTSTRAP_NODES];
static int num_bootstrap_nodes = 0;

static struct sockaddr_storage notify_addr = {0,};
static size_t notify_addr_len = {0,};

static volatile sig_atomic_t dumping = 0, searching = 0, exiting = 0;

static void
sigdump(int signo)
{
    dumping = 1;
}

static void
sigtest(int signo)
{
    searching = 1;
}

static void
sigexit(int signo)
{
    exiting = 1;
}

static void
init_signals(void)
{
    struct sigaction sa;
    sigset_t ss;
    
    sigemptyset(&ss);
    sa.sa_handler = sigdump;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);
    
    sigemptyset(&ss);
    sa.sa_handler = sigtest;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);
    
    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
}

unsigned char hash[20] = {
    0x54, 0x57, 0x87, 0x89, 0xdf, 0xc4, 0x23, 0xee, 0xf6, 0x03,
    0x1f, 0x81, 0x94, 0xa9, 0x3a, 0x16, 0x98, 0x8b, 0x72, 0x7b
};


#define CHECK(offset, delta, size)                      \
if(delta < 0 || offset + delta > size) goto fail

#define INC(offset, delta, size)                        \
CHECK(offset, delta, size);                         \
offset += delta

#define COPY(buf, offset, src, delta, size)             \
CHECK(offset, delta, size);                         \
memcpy(buf + offset, src, delta);                   \
offset += delta;

#define ADD_V(buf, offset, size)                        \
if(have_v) {                                        \
COPY(buf, offset, my_v, sizeof(my_v), size);    \
}

/* The call-back function is called by the DHT whenever something
 interesting happens.  Right now, it only happens when we get a new value or
 when a search completes, but this may be extended in future versions. */
static void
callback(void *closure,
         int event,
         unsigned char *info_hash,
         void *data, size_t data_len)
{
    if(event == DHT_EVENT_SEARCH_DONE) {
        printf("Search done.\n");
    } else if(event == DHT_EVENT_VALUES) {
        int i, rc, j;
        
        printf("Received %d values for ", (int)(data_len / 6));
        for(i = 0; i < 20; i++)
            printf("%02x", info_hash[i]);
        
        printf(".\n");
        
        char buf[512];
        i = 0;
        rc = snprintf(buf + i, 512 - i, "d1:t9:gotvalues"); INC(i, rc, 512);
        rc = snprintf(buf + i, 512 - i, "1:h20:"); INC(i, rc, 512);
        COPY(buf, i, info_hash, 20, 512);
        rc = snprintf(buf + i, 512 - i, "6:valuesl"); INC(i, rc, 512);
        
        int entries_to_send = (512 - i - 2) / (6 + 2);
        if(entries_to_send > (int)(data_len / 6)) {
            entries_to_send = (int)(data_len / 6);
        } else {
            printf("Warning: Truncated results list at %i entries\n", entries_to_send);
        }
        
        for(j = 0; j < entries_to_send; j++) {
            rc = snprintf(buf + i, 512 - i, "6:"); INC(i, rc, 512);
            COPY(buf, i, data + 6 * j, 6, 512);
        }
        
        rc = snprintf(buf + i, 512 - i, "ee"); INC(i, rc, 512);
        
        dht_send(buf, i, 0, (struct sockaddr *)&notify_addr, notify_addr_len);
    } else if(event == DHT_EVENT_VALUES6) {
        int i, rc, j;
        
        printf("Received %d IPv6 values for \n", (int)(data_len / 18));
        for(i = 0; i < 20; i++)
            printf("%02x", info_hash[i]);
        
        printf(".\n");
        
        char buf[512];
        i = 0;
        rc = snprintf(buf + i, 512 - i, "d1:t9:gotvalues"); INC(i, rc, 512);
        rc = snprintf(buf + i, 512 - i, "1:h20:"); INC(i, rc, 512);
        COPY(buf, i, info_hash, 20, 512);
        rc = snprintf(buf + i, 512 - i, "7:values6l"); INC(i, rc, 512);
        
        int entries_to_send = (512 - i - 2) / (18 + 3);
        if(entries_to_send > (int)(data_len / 18)) {
            entries_to_send = (int)(data_len / 18);
        } else {
            printf("Warning: Truncated results list at %i entries\n", entries_to_send);
        }
        
        for(j = 0; j < entries_to_send; j++) {
            rc = snprintf(buf + i, 512 - i, "18:"); INC(i, rc, 512);
            COPY(buf, i, data + 18 * j, 18, 512);
        }
        
        rc = snprintf(buf + i, 512 - i, "ee"); INC(i, rc, 512);
        
        dht_send(buf, i, 0, (struct sockaddr *)&notify_addr, notify_addr_len);
    } else if(event == DHT_EVENT_INFOHASH_SEEN) {
        int i, rc;
        
        printf("Saw infohash: ");
        
        for(i = 0; i < 20; i++)
            printf("%02x", info_hash[i]);
        
        printf(".\n");
        
        char buf[512];
        i = 0;
        rc = snprintf(buf + i, 512 - i, "d1:h20:"); INC(i, rc, 512);
        COPY(buf, i, info_hash, 20, 512);
        rc = snprintf(buf + i, 512 - i, "1:t7:sawhashe"); INC(i, rc, 512);
        
        dht_send(buf, i, 0, (struct sockaddr *)&notify_addr, notify_addr_len);
        
//        memcpy(hash, info_hash, 20);
//        searching = 1;
    }
fail:;
}

static unsigned char buf[4096];

int
main(int argc, char **argv)
{
    int i, rc, fd;
    int s = -1, s6 = -1, port;
    int have_id = 0;
    unsigned char myid[20];
    time_t tosleep = 0;
    char *id_file = "harvester.id";
    char *nodes_file = "nodes";
    int opt;
    int quiet = 0, ipv4 = 1, ipv6 = 1;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr_storage from;
    socklen_t fromlen;
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    
    
    
    while(1) {
        opt = getopt(argc, argv, "q46b:i:n:");
        if(opt < 0)
            break;
        
        switch(opt) {
            case 'q': quiet = 1; break;
            case '4': ipv6 = 0; break;
            case '6': ipv4 = 0; break;
            case 'b': {
                char buf[16];
                int rc;
                rc = inet_pton(AF_INET, optarg, buf);
                if(rc == 1) {
                    memcpy(&sin.sin_addr, buf, 4);
                    break;
                }
                rc = inet_pton(AF_INET6, optarg, buf);
                if(rc == 1) {
                    memcpy(&sin6.sin6_addr, buf, 16);
                    break;
                }
                goto usage;
            }
                break;
            case 'i':
                id_file = optarg;
                break;
            case 'n':
                nodes_file = optarg;
                break;
            default:
                goto usage;
        }
    }
    
    /* Ids need to be distributed evenly, so you cannot just use your
     bittorrent id.  Either generate it randomly, or take the SHA-1 of
     something. */
    fd = open(id_file, O_RDONLY);
    if(fd >= 0) {
        rc = read(fd, myid, 20);
        if(rc == 20)
            have_id = 1;
        close(fd);
    }
    
    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        perror("open(random)");
        exit(1);
    }
    
    if(!have_id) {
        int ofd;
        
        rc = read(fd, myid, 20);
        if(rc < 0) {
            perror("read(random)");
            exit(1);
        }
        have_id = 1;
        close(fd);
        
        ofd = open(id_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(ofd >= 0) {
            rc = write(ofd, myid, 20);
            if(rc < 20)
                unlink(id_file);
            close(ofd);
        }
    }
    
    {
        unsigned seed;
        read(fd, &seed, sizeof(seed));
        srandom(seed);
    }
    
    close(fd);
    
    if(argc < 2)
        goto usage;
    
    i = optind;
    
    if(argc < i + 1)
        goto usage;
    
    port = atoi(argv[i++]);
    if(port <= 0 || port >= 0x10000)
        goto usage;
    
    // notify host
    {
        if(argc < i + 2)
            goto usage;
        
        const char *notify_host = argv[i++];
        const char *notify_port = argv[i++];
        
        struct addrinfo hints, *info, *infop;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_DGRAM;
        if(!ipv6)
            hints.ai_family = AF_INET;
        else if(!ipv4)
            hints.ai_family = AF_INET6;
        else
            hints.ai_family = 0;
        rc = getaddrinfo(notify_host, notify_port, &hints, &info);
        if(rc != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
            exit(1);
        }
        
        infop = info;
        if(infop) {
            memcpy(&notify_addr,
                   infop->ai_addr, infop->ai_addrlen);
            notify_addr_len = infop->ai_addrlen;
            infop = infop->ai_next;
        }
        freeaddrinfo(info);
    }
    
    // default bootstrap
    {
        struct addrinfo hints, *info, *infop;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_DGRAM;
        if(!ipv6)
            hints.ai_family = AF_INET;
        else if(!ipv4)
            hints.ai_family = AF_INET6;
        else
            hints.ai_family = 0;
        rc = getaddrinfo("dht.transmissionbt.com", "6881", &hints, &info);
        if(rc != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
            exit(1);
        }
                
        infop = info;
        while(infop) {
            memcpy(&bootstrap_nodes[num_bootstrap_nodes],
                   infop->ai_addr, infop->ai_addrlen);
            infop = infop->ai_next;
            num_bootstrap_nodes++;
        }
        freeaddrinfo(info);
    }
    
    // bootstrap from known nodes
    {
        int i;
        
        FILE *nodesin = fopen(nodes_file, "rb");
        if(nodesin) {
            int total;
            fread(&total, sizeof(int), 1, nodesin);
            
            for(i = 0; i < total; i++) {
                if(num_bootstrap_nodes >= MAX_BOOTSTRAP_NODES)
                    break;
                
                fread(&bootstrap_nodes[num_bootstrap_nodes++], sizeof(struct sockaddr_storage), 1, nodesin);
            }
                       
            fclose(nodesin);
        }
    }
    
    /* If you set dht_debug to a stream, every action taken by the DHT will
     be logged. */
    if(!quiet)
        dht_debug = stdout;
    
    /* We need an IPv4 and an IPv6 socket, bound to a stable port.  Rumour
     has it that uTorrent works better when it is the same as your
     Bittorrent port. */
    if(ipv4) {
        s = socket(PF_INET, SOCK_DGRAM, 0);
        if(s < 0) {
            perror("socket(IPv4)");
        }
    }
    
    if(ipv6) {
        s6 = socket(PF_INET6, SOCK_DGRAM, 0);
        if(s6 < 0) {
            perror("socket(IPv6)");
        }
    }
    
    if(s < 0 && s6 < 0) {
        fprintf(stderr, "Eek!");
        exit(1);
    }
    
    
    if(s >= 0) {
        sin.sin_port = htons(port);
        rc = bind(s, (struct sockaddr*)&sin, sizeof(sin));
        if(rc < 0) {
            perror("bind(IPv4)");
            exit(1);
        }
    }
    
    if(s6 >= 0) {
        int rc;
        int val = 1;
        
        rc = setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY,
                        (char *)&val, sizeof(val));
        if(rc < 0) {
            perror("setsockopt(IPV6_V6ONLY)");
            exit(1);
        }
        
        /* BEP-32 mandates that we should bind this socket to one of our
         global IPv6 addresses.  In this simple example, this only
         happens if the user used the -b flag. */
        
        sin6.sin6_port = htons(port);
        rc = bind(s6, (struct sockaddr*)&sin6, sizeof(sin6));
        if(rc < 0) {
            perror("bind(IPv6)");
            exit(1);
        }
    }
    
    /* Init the dht.  This sets the socket into non-blocking mode. */
    rc = dht_init(s, s6, myid, (unsigned char*)"JC\0\0");
    if(rc < 0) {
        perror("dht_init");
        exit(1);
    }
    
    init_signals();
    
    /* For bootstrapping, we need an initial list of nodes.  This could be
     hard-wired, but can also be obtained from the nodes key of a torrent
     file, or from the PORT bittorrent message.
     
     Dht_ping_node is the brutal way of bootstrapping -- it actually
     sends a message to the peer.  If you're going to bootstrap from
     a massive number of nodes (for example because you're restoring from
     a dump) and you already know their ids, it's better to use
     dht_insert_node.  If the ids are incorrect, the DHT will recover. */
    
    printf("Bootstrapping from %i nodes\n", num_bootstrap_nodes);
    
    for(i = 0; i < num_bootstrap_nodes; i++) {
        dht_ping_node((struct sockaddr*)&bootstrap_nodes[i],
                      sizeof(bootstrap_nodes[i]));
        usleep(random() % 100000);
    }
    
    printf("Bootstrap done\n");
    
    while(1) {
        struct timeval tv;
        fd_set readfds;
        tv.tv_sec = tosleep;
        tv.tv_usec = random() % 1000000;
        
        FD_ZERO(&readfds);
        if(s >= 0)
            FD_SET(s, &readfds);
        if(s6 >= 0)
            FD_SET(s6, &readfds);
        rc = select(s > s6 ? s + 1 : s6 + 1, &readfds, NULL, NULL, &tv);
        if(rc < 0) {
            if(errno != EINTR) {
                perror("select");
                sleep(1);
            }
        }
        
        if(exiting)
            break;
        
        if(rc > 0) {
            fromlen = sizeof(from);
            if(s >= 0 && FD_ISSET(s, &readfds))
                rc = recvfrom(s, buf, sizeof(buf) - 1, 0,
                              (struct sockaddr*)&from, &fromlen);
            else if(s6 >= 0 && FD_ISSET(s6, &readfds))
                rc = recvfrom(s6, buf, sizeof(buf) - 1, 0,
                              (struct sockaddr*)&from, &fromlen);
            else
                abort();
        }
        
        if(rc > 0) {
            buf[rc] = '\0';
            rc = dht_periodic(buf, rc, (struct sockaddr*)&from, fromlen,
                              &tosleep, callback, NULL);
        } else {
            rc = dht_periodic(NULL, 0, NULL, 0, &tosleep, callback, NULL);
        }
        if(rc < 0) {
            if(errno == EINTR) {
                continue;
            } else {
                perror("dht_periodic");
                if(rc == EINVAL || rc == EFAULT)
                    abort();
                tosleep = 1;
            }
        }
        
        /* This is how you trigger a search for a torrent hash.  If port
         (the second argument) is non-zero, it also performs an announce.
         Since peers expire announced data after 30 minutes, it's a good
         idea to reannounce every 28 minutes or so. */
        if(searching) {
            if(s >= 0)
                dht_search(hash, 0, AF_INET, callback, NULL);
            if(s6 >= 0)
                dht_search(hash, 0, AF_INET6, callback, NULL);
            searching = 0;
        }
        
        /* For debugging, or idle curiosity. */
        if(dumping) {
            dht_dump_tables(stdout);
            dumping = 0;
        }
    }
    
    {
        struct sockaddr_in sin[500];
        struct sockaddr_in6 sin6[500];
        int num = 500, num6 = 500;
        int i;
        i = dht_get_nodes(sin, &num, sin6, &num6);
        printf("Saving %d (%d + %d) good nodes.\n", i, num, num6);
        
        FILE *nodesout = fopen(nodes_file, "wb");
        if(nodesout) {
            int total = num + num6;
            fwrite(&total, sizeof(int), 1, nodesout);
            
            for(i = 0; i < num; i++) {
                struct sockaddr_storage storage = {0, };
                
                memcpy(&storage, &sin[i], sizeof(sin[i]));
                fwrite(&storage, sizeof(storage), 1, nodesout);
            }
            
            for(i = 0; i < num6; i++) {
                struct sockaddr_storage storage = {0, };
                
                memcpy(&storage, &sin6[i], sizeof(sin6[i]));
                fwrite(&storage, sizeof(storage), 1, nodesout);
            }
            
            fclose(nodesout);
        }
    }
    
    dht_uninit();
    return 0;
    
usage:
    printf("Usage: dht-harvester [-q] [-4] [-6] [-i filename] [-b address] [-n filename] listen-port notify-host notify-port\n");
    exit(1);
}

/* We need to provide a reasonably strong cryptographic hashing function.
 Here's how we'd do it if we had RSA's MD5 code. */
#if 1
void
dht_hash(void *hash_return, int hash_size,
         const void *v1, int len1,
         const void *v2, int len2,
         const void *v3, int len3)
{
    static MD5_CTX ctx;
    unsigned char md[MD5_DIGEST_LENGTH];
    
    MD5_Init(&ctx);
    MD5_Update(&ctx, v1, len1);
    MD5_Update(&ctx, v2, len2);
    MD5_Update(&ctx, v3, len3);
    MD5_Final(md, &ctx);
    if(hash_size > MD5_DIGEST_LENGTH)
        memset((char*)hash_return + MD5_DIGEST_LENGTH, 0, hash_size - MD5_DIGEST_LENGTH);
    memcpy(hash_return, md, hash_size > MD5_DIGEST_LENGTH ? MD5_DIGEST_LENGTH : hash_size);
}
#else
/* But for this example, we might as well use something weaker. */
void
dht_hash(void *hash_return, int hash_size,
         const void *v1, int len1,
         const void *v2, int len2,
         const void *v3, int len3)
{
    const char *c1 = v1, *c2 = v2, *c3 = v3;
    char key[9];                /* crypt is limited to 8 characters */
    int i;
    
    memset(key, 0, 9);
#define CRYPT_HAPPY(c) ((c % 0x60) + 0x20)
    
    for(i = 0; i < 2 && i < len1; i++)
        key[i] = CRYPT_HAPPY(c1[i]);
    for(i = 0; i < 4 && i < len1; i++)
        key[2 + i] = CRYPT_HAPPY(c2[i]);
    for(i = 0; i < 2 && i < len1; i++)
        key[6 + i] = CRYPT_HAPPY(c3[i]);
    strncpy(hash_return, crypt(key, "jc"), hash_size);
}
#endif

int
dht_random_bytes(void *buf, size_t size)
{
    int fd, rc, save;
    
    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0)
        return -1;
    
    rc = read(fd, buf, size);
    
    save = errno;
    close(fd);
    errno = save;
    
    return rc;
}

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>

#define ns_t_rrsig 46
#define ns_t_dnskey 48

static int eof = 0;
static int maxfd = -1;
static fd_set rfds, wfds;
static int outstanding;
static int maxoutstanding = 100;

static void(*rhandlers[FD_SETSIZE])(int);
static void(*whandlers[FD_SETSIZE])(int);

static int udp4 = -1;
static int udp6 = -1;
static int debug = 0;

static union res_sockaddr_union servers[10];
static int nservers = 0;

#define APPEND(list, item, link) do { \
	if ((list).tail) \
		(list).tail->link.next = (item); \
	else \
		(list).head = (item); \
	(item)->link.prev = list.tail; \
	(item)->link.next = NULL; \
	(item)->link.linked = 1; \
	(list).tail = (item); \
} while (0)

#define UNLINK(list, item, link) do { \
	if ((item)->link.next) \
		(item)->link.next->link.prev = (item)->link.prev; \
	else \
		list.tail = (item)->link.prev; \
	if ((item)->link.prev) \
		(item)->link.prev->link.next = (item)->link.next; \
	else \
		list.head = (item)->link.next; \
	(item)->link.next = (item)->link.prev = NULL; \
	(item)->link.linked = 0; \
} while (0)

#define NEXT(item, link) (item)->link.next
#define PREV(item, link) (item)->link.next
#define LINKED(item, link) (item)->link.linked

#define HEAD(list) (list).head
#define TAIL(list) (list).tail

struct {
	const char *name;
	unsigned short rdlen;
	const char *rdata;
	unsigned short udpsize;
	unsigned short flags;
	unsigned short version;
	unsigned int tcp;
	unsigned int ignore;
	unsigned short type;
} opts[] = {
	{ "dns", 0, NULL, 0, 0, 0, 0, 0, ns_t_soa },
	{ "edns", 0, "", 4096, 0, 0, 0, 0, ns_t_soa },
	{ "edns1", 0, "" , 4096, 0, 1, 0, 0, ns_t_soa },
	{ "edns@512", 0, "" , 512, 0, 0, 0, 1, ns_t_dnskey },
	{ "ednsopt", 4, "\x00\x64\x00", 4096, 0, 0, 0, 0, ns_t_soa },
	{ "edns1opt", 4, "\x00\x64\x00", 4096, 0, 1, 0, 0, ns_t_soa },
	{ "do", 4, "\0\144\0", 4096, 0x8000, 0, 0, 0, ns_t_soa },
	{ "ednsflags", 0, "", 4096, 0x80, 0, 0, 0, ns_t_soa },
	{ "optlist", 4 + 8 + 4 + 12,
	  "\x00\x03\x00\x00" 		     /* NSID */
	  "\x00\x08\x00\x04\x00\x01\x00\x00" /* ECS */
	  "\x00\x09\x00\x00" 		     /* EXPIRE */
	  "\x00\x0a\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08",	/* COOKIE */
	  4096, 0, 0, 0, 0, ns_t_soa },
/*
	{ "bind", 12, "\x00\x0a\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08",
	  4096, 1, 0, 0, 0, ns_t_soa },
*/
	{ "ednstcp", 0, "", 512, 1, 0, 1, 0, ns_t_dnskey }
};

struct summary {
	char zone[1024];
	char ns[1024];
	struct sockaddr_storage storage;
	int tests;
	int done;
	int type;
	int nodataa;
	int nodataaaa;
	int nxdomain;
	int nxdomaina;
	int nxdomainaaaa;
	int seenrrsig;
	struct summary *xlink;
	char results[sizeof(opts)/sizeof(opts[0])][100];
};

struct workitem {
	struct {
		struct workitem *next;
		struct workitem *prev;
		int linked;
	} link, clink, rlink, idlink;
	unsigned short id;
	struct timeval when;
	int type;
	int test;
	int sends;
	int buflen;
	int tcpfd;
	int outstanding;
	int havelen;
	int readlen;
	int read;
	unsigned char buf[512];
	unsigned char tcpbuf[0x10000];
	char result[100];
	struct summary *summary;
};

static struct {
	struct workitem *head;
	struct workitem *tail;
} work, connecting, reading, ids[0x10000];

static void
connecttoserver(struct workitem *item);

static int
storage_equal(struct sockaddr_storage *s1, struct sockaddr_storage *s2) {
	struct sockaddr_in *sin1, *sin2;
	struct sockaddr_in6 *sin61, *sin62;

	if (s1->ss_len != s2->ss_len || s1->ss_family != s2->ss_family)
		return (0);

	switch (s1->ss_family) {
	case AF_INET:
		sin1 = (struct sockaddr_in *)s1;
		sin2 = (struct sockaddr_in *)s2;
			
		if (sin1->sin_port != sin2->sin_port ||
		    sin1->sin_addr.s_addr != sin2->sin_addr.s_addr)
			return (0);
		return (1);
	case AF_INET6:
		sin61 = (struct sockaddr_in6 *)s1;
		sin62 = (struct sockaddr_in6 *)s2;

		if (sin61->sin6_port != sin62->sin6_port ||
		    memcmp(&sin61->sin6_addr, &sin62->sin6_addr, 16) != 0)
			return (0);
		return (1);
	}
	return (0);
}

static int
checkid(struct sockaddr_storage *storage, int id) {
	struct workitem *item;

	item = HEAD(ids[id]);
	while (item != NULL &&
	       !storage_equal(storage, &item->summary->storage))
		item = NEXT(item, idlink);
	return ((item == NULL) ? 1 : 0);
}

static void
report(struct summary *summary) {
	struct sockaddr_in *s = (struct sockaddr_in *)&summary->storage;
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&summary->storage;;
	char addrbuf[64];
	void *addr;
	unsigned int i;
	int x;

	summary->tests--;
	if (summary->tests)
		return;

	if (summary->xlink) {
		if (summary->nodataa)
			summary->xlink->nodataa = 1;
		if (summary->nodataaaa)
			summary->xlink->nodataaaa = 1;
		if (summary->nxdomaina)
			summary->xlink->nxdomaina = 1;
		if (summary->nxdomainaaaa)
			summary->xlink->nxdomainaaaa = 1;
		summary->xlink->xlink = NULL;
		summary->xlink = NULL;
		summary->done = 1;
	}

	if ((summary->type == ns_t_a || summary->type == ns_t_aaaa) &&
	    summary->nodataa && summary->nodataaaa) {
		printf("%s. %s: no address records found\n",
		       summary->zone, summary->ns);
		free(summary);
		return;
	}
	if ((summary->type == ns_t_a || summary->type == ns_t_aaaa) &&
	    summary->nxdomaina && summary->nxdomainaaaa) {
		printf("%s. %s: no address records found (NXDOMAIN)\n",
		       summary->zone, summary->ns);
		free(summary);
		return;
	}

	if (summary->done) {
		free(summary);
		return;
	}
	
	if (summary->storage.ss_family == AF_INET)
		addr = &s->sin_addr;
	else
		addr = &s6->sin6_addr;
	inet_ntop(summary->storage.ss_family, addr, addrbuf, sizeof(addrbuf));
	if (summary->type != 0 && summary->nxdomain) {
		if (summary->type == ns_t_ns) {
			printf("%s.: NS nxdomain\n", summary->zone);
			free(summary);
			return;
		}
		printf("%s. %s:", summary->zone, summary->ns);
		if (summary->type == ns_t_a) printf(" A");
		if (summary->type == ns_t_aaaa) printf(" AAAA");
		printf(" nxdomain\n");
		free(summary);
		return;
	}
	if (summary->type == ns_t_a) {
		printf("%s. %s:", summary->zone, summary->ns);
		printf(" A lookup failed\n");
		free(summary);
		return;
	}
	if (summary->type == ns_t_aaaa) {
		printf("%s. %s:", summary->zone, summary->ns);
		printf(" AAAA lookup failed\n");
		free(summary);
		return;
	}
	if (summary->type == ns_t_ns) {
		printf("%s. %s:", summary->zone, summary->ns);
		printf(" NS lookup failed\n");
		free(summary);
		return;
	}
	x = -1;
	printf("%s. @%s (%s.):", summary->zone, addrbuf, summary->ns);
	for (i = 0; i < sizeof(opts)/sizeof(opts[0]); i++) {
		if (summary->results[i][0] == 0)
			strcpy(summary->results[i], "skipped");
		if (strcmp(opts[i].name, "do") == 0)
			x = i;
		if (strcmp(opts[i].name, "ednstcp") == 0 && x != -1) {
			printf(" signed=%s", summary->results[x]);
			if (summary->seenrrsig)
				printf(",yes");
		}
		printf(" %s=%s", opts[i].name, summary->results[i]);
	}
	printf("\n");
	free(summary);
}

static void
freeitem(struct workitem * item) {
	report(item->summary);
	if (item->tcpfd != 0) {
		FD_CLR(item->tcpfd, &rfds);
		FD_CLR(item->tcpfd, &wfds);
		rhandlers[item->tcpfd] = NULL;
		whandlers[item->tcpfd] = NULL;
		close(item->tcpfd);
	}
	if (item->outstanding)
		outstanding--;
	if (LINKED(item, link))
		UNLINK(work, item, link);
	if (LINKED(item, rlink))
		UNLINK(reading, item, rlink);
	if (LINKED(item, clink))
		UNLINK(connecting, item, clink);
	if (LINKED(item, idlink))
		UNLINK(ids[item->id], item, idlink);
	free(item);
}

static void
addtag(struct workitem *item, char *tag) {
	char *result = item->summary->results[item->test];
	int i = strlen(result);
	if (i)
		result[i++] = ',';
	strcpy(result + i, tag);
}

static void
resend(struct workitem *item) {
	unsigned int ttl;
	int n, fd = -1;

	switch (item->summary->storage.ss_family) {
	case AF_INET:
		fd = udp4;
		break;
	case AF_INET6:
		fd = udp6;
		break;
	}

	if (fd == -1) {
		addtag(item, "skipped");
		freeitem(item);
		return;
	}

	if (outstanding > maxoutstanding) {
		gettimeofday(&item->when, NULL);
		item->when.tv_sec += 1;
		UNLINK(work, item, link);
		APPEND(work, item, link);
		return;
	}

	n = sendto(fd, item->buf, item->buflen, 0,
		   (struct sockaddr *)&item->summary->storage,
		   item->summary->storage.ss_len);
	if (n > 0) {
		if (debug)
			printf("resend %s rdlen=%u udpsize=%u flags=%04x "
			       "version=%u tcp=%u ignore=%u id=%u\n",
			       opts[item->test].name, opts[item->test].rdlen,
			       opts[item->test].udpsize, opts[item->test].flags,
			       opts[item->test].version, opts[item->test].tcp,
			       opts[item->test].ignore, item->id);
		if (!item->outstanding++)
			outstanding++;
		gettimeofday(&item->when, NULL);
		item->when.tv_sec += 1;
		item->sends++;
		UNLINK(work, item, link);
		APPEND(work, item, link);
	} else {
		addtag(item, "failed");
		freeitem(item);
	}
}

static void
dotest(struct workitem *item) {
	unsigned char *cp;
	unsigned int ttl;
	int n, fd, id, tries = 0;

	switch (item->summary->storage.ss_family) {
	case AF_INET:
		fd = udp4;
		break;
	case AF_INET6:
		fd = udp6;
		break;
	}

	if (fd == -1) {
		addtag(item, "skipped");
		freeitem(item);
		return;
	}
	
	n = res_mkquery(ns_o_query, item->summary->zone, ns_c_in,
			opts[item->test].type, NULL, 0, NULL,
			item->buf, sizeof(item->buf));
	item->buf[2] &= ~0x1;	/* clear rd */
	if (n > 0) {
		char name[1024];
		dn_expand(item->buf, item->buf + n, item->buf + 12,
			  name, sizeof(name));
		strcpy(item->summary->zone, name);
	}
	
	if (n > 0 && opts[item->test].udpsize > 0) {
		cp = item->buf + n;
		*cp++ = 0;				/* name */
		ns_put16(ns_t_opt, cp);			/* type */
		cp += 2;
		ns_put16(opts[item->test].udpsize, cp);	/* class */
		cp += 2;
		ttl = (opts[item->test].version << 16) |
		      opts[item->test].flags;
		ns_put32(ttl, cp);			/* ttl */
		cp += 4;
		ns_put16(opts[item->test].rdlen, cp);	/* rdlen */
		cp += 2;
		memcpy(cp, opts[item->test].rdata, opts[item->test].rdlen);
		cp += opts[item->test].rdlen;
		item->buf[11] = 1;			/* adcount */
		n = cp - item->buf;			/* total length */
	}

	if (n > 0) {
		id = item->buf[0] << 8 | item->buf[1];

		while (!checkid(&item->summary->storage, id) &&
		       tries++ < 0xffff)
			id = (id + 1) & 0xffff;
		
		if (tries == 0xffff) {
			addtag(item, "skipped");
			freeitem(item);
			return;
		}
 
		item->buf[0] = id >> 8;
		item->buf[1] = id & 0xff;
		item->id = id;
		item->buflen = n;

		if (opts[item->test].tcp) {
			connecttoserver(item);
			return;
		}

		if (outstanding > maxoutstanding) {
			gettimeofday(&item->when, NULL);
			item->when.tv_sec += 1;
			APPEND(work, item, link);
			APPEND(ids[item->id], item, idlink);
			return;
		}

		n = sendto(fd, item->buf, item->buflen, 0,
			   (struct sockaddr *)&item->summary->storage,
			   item->summary->storage.ss_len);
	}

	if (n > 0) {
		if (debug)
			printf("%s rdlen=%u udpsize=%u flags=%04x version=%u "
			       "tcp=%u ignore=%u id=%u\n",
			       opts[item->test].name, opts[item->test].rdlen,
			       opts[item->test].udpsize, opts[item->test].flags,
			       opts[item->test].version, opts[item->test].tcp,
			       opts[item->test].ignore, item->id);
		if (!item->outstanding++)
			outstanding++;
		gettimeofday(&item->when, NULL);
		item->when.tv_sec += 1;
		item->sends = 1;
		APPEND(work, item, link);
		APPEND(ids[item->id], item, idlink);
	} else {
		addtag(item, "failed");
		freeitem(item);
	}
}

static void
check(char *zone, char *ns, char *address) {
	size_t i;
	int n, fd;
	struct in_addr addr;
	struct in6_addr addr6;
	struct sockaddr_storage storage;
	struct summary *summary;
	
	memset(&storage, 0, sizeof(storage));
	if (inet_pton(AF_INET6, address, &addr6) == 1) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&storage;
		s->sin6_len = sizeof(struct sockaddr_in6);
		s->sin6_family = AF_INET6;
		s->sin6_port = htons(53);
		s->sin6_addr = addr6;
		fd = udp6;
	} else if (inet_pton(AF_INET, address, &addr) == 1) {
		struct sockaddr_in *s = (struct sockaddr_in *)&storage;
		s->sin_len = sizeof(struct sockaddr_in);
		s->sin_family = AF_INET;
		s->sin_port = htons(53);
		s->sin_addr = addr;
		fd = udp4;
	} else
		return;

	if (fd == -1)
		return;

	summary = calloc(1, sizeof(*summary));
	if (summary == NULL)
		return;
	summary->storage = storage;
	ns_makecanon(zone, summary->zone, sizeof(summary->zone));
	i = strlen(summary->zone);
	if (i) summary->zone[i-1] = 0;
	ns_makecanon(ns, summary->ns, sizeof(summary->ns));
	i = strlen(summary->ns);
	if (i) summary->ns[i-1] = 0;
	for (i = 0; i < sizeof(opts)/sizeof(opts[0]); i++) {
		struct workitem *item = calloc(1, sizeof(*item));
		if (item == NULL) {
			summary->tests++;
			report(summary);
			break;
		}
		summary->tests++;
		item->summary = summary;
		item->test = i;
		dotest(item);
	}
}

static char *
rcodetext(int code) {
	static char buf[64];
	switch(code) {
	case 0: return("noerror");
	case 1: return("formerr");
	case 2: return("servfail");
	case 3: return("nxdomain");
	case 4: return("notimpl");
	case 5: return("refused");
	case 6: return("yxdomain");
	case 7: return("yxrrset");
	case 8: return("nxrrset");
	case 9: return("notauth");
	case 10: return("notzone");
	case 16: return("badvers");
	case 23: return("badcookie");
	default:
		snprintf(buf, sizeof(buf), "?%u", code);
		return (buf);
	}
}

static void
dolookup(struct workitem *item, int type) {
	char name[1024];
	int n, fd = -1;

	item->summary->tests++;
	item->summary->type = item->type = type;

 again:
	if (servers[item->test].sin.sin_family == AF_INET)
		memcpy(&item->summary->storage, &servers[item->test].sin,
		       sizeof(servers[item->test].sin));
	else
		memcpy(&item->summary->storage, &servers[0].sin6,
		       sizeof(servers[item->test].sin6));

	switch (item->summary->storage.ss_family) {
	case AF_INET:
		fd = udp4;
		break;
	case AF_INET6:
		fd = udp6;
		break;
	}

	if (fd == -1) {
		if (++item->test < nservers)
			goto again;
		addtag(item, "skipped");
		freeitem(item);
		return;
	}
	
	if (type == ns_t_ns)
		n = res_mkquery(ns_o_query, item->summary->zone, ns_c_in,
				type, NULL, 0, NULL,
				item->buf, sizeof(item->buf));
	else
		n = res_mkquery(ns_o_query, item->summary->ns, ns_c_in,
				type, NULL, 0, NULL,
				item->buf, sizeof(item->buf));
	if (n > 0) {
		int id = item->buf[0] << 8 | item->buf[1];
		int tries = 0;

		dn_expand(item->buf, item->buf + n, item->buf + 12,
			 name, sizeof(name));
		if (type == ns_t_ns)
			strcpy(item->summary->zone, name);
		else
			strcpy(item->summary->ns, name);

		while (!checkid(&item->summary->storage, id) &&
		       tries++ < 0xffff)
			id = (id + 1) & 0xffff;
		
		if (tries == 0xffff) {
			addtag(item, "skipped");
			freeitem(item);
			return;
		}

		item->buf[0] = id >> 8;
		item->buf[1] = id & 0xff;
		item->id = id;
		item->buflen = n;
		if (outstanding > maxoutstanding) {
			gettimeofday(&item->when, NULL);
			item->when.tv_sec += 1;
			APPEND(work, item, link);
			APPEND(ids[item->id], item, idlink);
			return;
		}
		n = sendto(fd, item->buf, item->buflen, 0,
			   (struct sockaddr *)&item->summary->storage,
			   item->summary->storage.ss_len);
	}
	if (n > 0) {
		if (debug)
			printf("lookup %u id=%u\n", item->type, item->id);
		if (!item->outstanding++)
			outstanding++;
		gettimeofday(&item->when, NULL);
		item->when.tv_sec += 1;
		item->sends++;
		APPEND(work, item, link);
		APPEND(ids[item->id], item, idlink);
	} else {
		addtag(item, "skipped");
		freeitem(item);
	}
}

static struct summary *
lookupa(char *zone, char *ns) {
	struct summary *summary;
	struct workitem *item;
	unsigned int i;

	summary = calloc(1, sizeof(*summary));
	if (summary == NULL)
		return (NULL);

	ns_makecanon(zone, summary->zone, sizeof(summary->zone));
	i = strlen(summary->zone);
	if (i) summary->zone[i-1] = 0;

	ns_makecanon(ns, summary->ns, sizeof(summary->ns));
	i = strlen(summary->ns);
	if (i) summary->ns[i-1] = 0;

	item = calloc(1, sizeof(*item));
	if (item == NULL)
		free(summary);

	item->summary = summary;
	dolookup(item, ns_t_a);
	return (summary);
}

static struct summary *
lookupaaaa(char *zone, char *ns) {
	struct summary *summary;
	struct workitem *item;
	unsigned int i;

	summary = calloc(1, sizeof(*summary));
	if (summary == NULL)
		return (NULL);

	ns_makecanon(zone, summary->zone, sizeof(summary->zone));
	i = strlen(summary->zone);
	if (i) summary->zone[i-1] = 0;

	ns_makecanon(ns, summary->ns, sizeof(summary->ns));
	i = strlen(summary->ns);
	if (i) summary->ns[i-1] = 0;

	item = calloc(1, sizeof(*item));
	if (item == NULL)
		free(summary);

	item->summary = summary;
	dolookup(item, ns_t_aaaa);
	return (summary);
}

static void
lookupns(char *zone) {
	struct summary *summary;
	struct workitem *item;
	unsigned int i;

	summary = calloc(1, sizeof(*summary));
	if (summary == NULL)
		return;
	strcpy(summary->zone, zone);

	item = calloc(1, sizeof(*item));
	if (item == NULL)
		free(summary);

	item->summary = summary;
	dolookup(item, ns_t_ns);
}

static void
process(struct workitem *item, unsigned char *buf, int n) {
	char name[1024], ns[1024];
	unsigned int i, id, qr, aa, tc, rd, ra, z, ad, cd;
	unsigned int qrcount, ancount, aucount, adcount;
	unsigned int opcode, rcode;
	unsigned int type, ednssize = 0, class, ednsttl = 0, ttl, rdlen;
	unsigned char *cp, *eom; 	
	int seenopt = 0, seensoa = 0, seenrrsig = 0;
	int seennsid = 0, seenecs = 0, seenexpire = 0, seencookie = 0;
	int seenecho = 0;
	char addrbuf[64];
	struct sockaddr_in *s = (struct sockaddr_in *)&item->summary->storage;
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&item->summary->storage;
	void *addr;
	int ok = 1;

	/* process message header */

	id = buf[0] << 8| buf[1];
	qr = (buf[2] >> 7) & 0x1;
	opcode = (buf[2] >> 3) & 0xf;
	aa = (buf[2] >> 2) & 0x1;
	tc = (buf[2] >> 1) & 0x1;
	rd = buf[2] & 0x1;
	ra = (buf[3] >> 7) & 0x1;
	z = (buf[3] >> 6) & 0x1;
	ad = (buf[3] >> 5) & 0x1;
	cd = (buf[3] >> 4) & 0x1;
	rcode = buf[3] & 0xf;
	qrcount = buf[4] << 8 | buf[5];
	ancount = buf[6] << 8 | buf[7];
	aucount = buf[8] << 8 | buf[9];
	adcount = buf[10] << 8 | buf[11];

	if (tc && !opts[item->test].ignore && item->tcpfd == 0) {
		if (LINKED(item, link))
			UNLINK(work, item, link);
		connecttoserver(item);
		return;
	}

	/* process message body */

	if (item->type == ns_t_a || item->type == ns_t_aaaa)
		strcpy(ns, item->summary->ns);

	cp = buf + 12;
	eom = buf + n;
	for (i = 0; i < qrcount; i++) {
		n = dn_expand(buf, eom, cp, name, sizeof(name));
		if (n < 0 || (eom - cp) < n)
			goto err;
		cp += n;
		if ((eom - cp) < 4)
			goto err;
		type = ns_get16(cp);
		cp += 2;
		class = ns_get16(cp);
		cp += 2;
		if (debug)
			printf("QR: %s./%u/%u\n", name, type, class);

		/*
		 * No address / NS records?
		 */
		if (item->type == ns_t_a && type == ns_t_a &&
		    strcasecmp(item->summary->ns, name) == 0 &&
		    rcode == 0 && ancount == 0) {
			item->summary->done = 1;
			item->summary->nodataa = 1;
		}
		if (item->type == ns_t_aaaa && type == ns_t_aaaa &&
		    strcasecmp(item->summary->ns, name) == 0 &&
		    rcode == 0 && ancount == 0) {
			item->summary->done = 1;
			item->summary->nodataaaa = 1;
		}
		if (item->type == ns_t_ns && type == ns_t_ns &&
		    strcasecmp(item->summary->zone, name) == 0 &&
		    rcode == 0 && ancount == 0)
			item->summary->done = 1;

		/*
		 * NXDOMAIN?
		 */
		if (item->type == ns_t_a && type == ns_t_a &&
		    strcasecmp(item->summary->ns, name) == 0 &&
		    rcode == 3 && ancount == 0)
			item->summary->nxdomaina = 1;
		if (item->type == ns_t_aaaa && type == ns_t_aaaa &&
		    strcasecmp(item->summary->ns, name) == 0 &&
		    rcode == 3 && ancount == 0)
			item->summary->nxdomainaaaa = 1;
		if (item->type == ns_t_ns && type == ns_t_ns &&
		    strcasecmp(item->summary->zone, name) == 0 &&
		    rcode == 3 && ancount == 0)
			item->summary->nxdomain = 1;
	}

	for (i = 0; i < ancount; i++) {
		n = dn_expand(buf, eom, cp, name, sizeof(name));
		if (n < 0 || (eom - cp) < n)
			goto err;
		cp += n;
		if ((eom - cp) < 8)
			goto err;
		type = ns_get16(cp);
		cp += 2;
		class = ns_get16(cp);
		cp += 2;
		ttl = ns_get32(cp);
		cp += 4;
		rdlen = ns_get16(cp);
		cp += 2;
		if ((eom - cp) < rdlen)
			goto err;
		if ((item->type == ns_t_a || item->type == ns_t_aaaa) &&
		    type == ns_t_cname && strcasecmp(ns, name) == 0) {
			n = dn_expand(buf, eom, cp, ns, sizeof(ns));
			if (n != rdlen)
				goto err;
		}
		if (item->type == ns_t_a && type == ns_t_a &&
		    strcasecmp(ns, name) == 0)
		{
			if (rdlen != 4)
				goto err;
			inet_ntop(AF_INET, cp, addrbuf, sizeof(addrbuf));
			check(item->summary->zone, item->summary->ns, addrbuf);
			item->summary->done = 1;
		}
		if (item->type == ns_t_aaaa && type == ns_t_aaaa &&
		    strcasecmp(ns, name) == 0)
		{
			if (rdlen != 16)
				goto err;
			inet_ntop(AF_INET6, cp, addrbuf, sizeof(addrbuf));
			check(item->summary->zone, item->summary->ns, addrbuf);
			item->summary->done = 1;
		}
		if (item->type == ns_t_ns && type == ns_t_ns &&
		    strcasecmp(item->summary->zone, name) == 0)
		{
			struct summary *summarya, *summaryaaaa;
			n = dn_expand(buf, eom, cp, ns, sizeof(ns));
			if (n != rdlen)
				goto err;
			item->summary->done = 1;
			summarya = lookupa(item->summary->zone, ns);
			summaryaaaa = lookupaaaa(item->summary->zone, ns);
			if (summarya && summaryaaaa) {
				summarya->xlink = summaryaaaa;
				summaryaaaa->xlink = summarya;
			}
		}
		cp += rdlen;
		if (type == ns_t_soa &&
		    strcasecmp(item->summary->zone, name) == 0)
			seensoa = 1;
		else if (type == ns_t_soa)
		    printf("%s %s\n", item->summary->zone, name);
		if (type == ns_t_rrsig)
			seenrrsig = 1;
		if (debug)
			printf("AN: %s./%u/%u/%u/%u\n",
			       name, type, class, ttl, rdlen);
	}

	for (i = 0; i < aucount; i++) {
		n = dn_expand(buf, eom, cp, name, sizeof(name));
		if (n < 0 || (eom - cp) < n)
			goto err;
		cp += n;
		if ((eom - cp) < 8)
			goto err;
		type = ns_get16(cp);
		cp += 2;
		class = ns_get16(cp);
		cp += 2;
		ttl = ns_get32(cp);
		cp += 4;
		rdlen = ns_get16(cp);
		cp += 2;
		if ((eom - cp) < rdlen)
			goto err;
		cp += rdlen;
		if (debug)
			printf("AU: %s./%u/%u/%u/%u\n",
			       name, type, class, ttl, rdlen);
	}

	for (i = 0; i < adcount; i++) {
		n = dn_expand(buf, eom, cp, name, sizeof(name));
		if (n < 0 || (eom - cp) < n)
			goto err;
		cp += n;
		if ((eom - cp) < 8)
			goto err;
		type = ns_get16(cp);
		cp += 2;
		class = ns_get16(cp);
		cp += 2;
		ttl = ns_get32(cp);
		cp += 4;
		rdlen = ns_get16(cp);
		cp += 2;
		if ((eom - cp) < rdlen)
			goto err;
		if (type == ns_t_opt && !seenopt) {
			unsigned char *options;
			ednsttl = ttl;
			ednssize = class;
			seenopt = 1;
			options = cp;
			while (((cp + rdlen) - options) >= 4) {
				unsigned int code, optlen;
				code = ns_get16(options);
				options += 2;
				optlen = ns_get16(options);
				options += 2;
				if (code == 3 && optlen > 0)
					seennsid = 1;
				if (code == 8)
					seenecs = 1;
				if (code == 9 && optlen == 4)
					seenexpire = 1;
				if (code == 10 && optlen >= 16 && optlen <= 24)
					seencookie = 1;
				if (code == 100)
					seenecho = 1;
				options += optlen;
			}
			if (options != (cp + rdlen))
				goto err;
		}
		cp += rdlen;
		if (debug)
			printf("AD: %s./%u/%u/%u/%u\n",
			       name, type, class, ttl, rdlen);
	}
	if (cp != eom)
		goto err;

	rcode += (ednsttl & 0xff000000) >> 20;

	if (debug)
		printf("id=%-5u %-9s opcode=%u rcode=%u aa=%u tc=%u rd=%u "
		       "ra=%u z=%u ad=%u cd=%u qrcount=%u ancount=%u "
		       "aucount=%u adcount=%u\n"
		       "\tseensoa=%u seenrrsig=%u seenopt=%u "
		       "seennsid=%u seenecs=%u seenexpire=%u seencookie=%u\n",
		       id, opts[item->test].name, opcode, rcode,
		       aa, tc, rd, ra, z, ad, cd,
		       qrcount, ancount, aucount, adcount,
		       seensoa, seenrrsig, seenopt,
		       seennsid, seenecs, seenexpire, seencookie);
	if (opts[item->test].version == 0)
		if (rcode != 0)
			addtag(item, rcodetext(rcode)), ok = 0;
	if (opts[item->test].version != 0)
		if (rcode != 16) /* badvers */
			addtag(item, rcodetext(rcode)), ok = 0;
	if ((ednsttl & 0xff0000) != 0)
		addtag(item, "badversion"), ok = 0;
	if (opts[item->test].type == ns_t_soa)
		if (opts[item->test].version == 0 &&
		    !opts[item->test].ignore && !seensoa)
			addtag(item, "nosoa"), ok = 0;
	if (opts[item->test].type == ns_t_soa)
		if (opts[item->test].version != 0 && seensoa)
			addtag(item, "soa"), ok = 0;
	if (seenecho)
		addtag(item, "echoed"), ok = 0;
	if ((ednsttl & 0x8000) == 0 && seenrrsig)
		addtag(item, "nodo"), ok = 0;
	if ((ednsttl & 0x7fff) != 0)
		addtag(item, "mbz"), ok = 0;
	if (seenrrsig)
		item->summary->seenrrsig = 1;
	if (ok)
		addtag(item, "ok");
	if (seennsid)
		addtag(item, "nsid");
	if (seenexpire)
		addtag(item, "expire");
	if (seencookie)
		addtag(item, "cookie");
	if (seenecs)
		addtag(item, "subnet");
		
	goto done;
 err:
	addtag(item, "malformed");
 done:
	freeitem(item);
}

static void
tcpread(int fd) {
	struct workitem *item;
	int n;

	item = HEAD(reading);
	while (item && item->tcpfd != fd)
		item = NEXT(item, rlink);
	if (item == NULL)
		return;
 again:
	n = read(fd, item->tcpbuf + item->read, item->readlen - item->read);
	if (n == 0) {
		addtag(item, "eof");
		freeitem(item);
		return;
	}
	if (n < 0 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n < 0) {
		if (errno == ECONNRESET)
			addtag(item, "reset");
		else if (errno == EPIPE)
			addtag(item, "pipe");
		else 
			addtag(item, "read");
		freeitem(item);
		return;
	} 
	item->read += n;
	if (item->read == item->readlen) {
		if (!item->havelen) {
			item->readlen = item->tcpbuf[0] << 8 | item->tcpbuf[1];
			item->havelen = 1;
			item->read = 0;
			goto again;
		}
		process(item, item->tcpbuf, item->readlen);
	}
}

static void
startread(struct workitem *item) {
	struct iovec iov[2];
	int iovcnt = 2;
	unsigned char buf[2];
	int n;

	FD_SET(item->tcpfd, &rfds);
	if (item->tcpfd > maxfd)
		maxfd = item->tcpfd;
	rhandlers[item->tcpfd] = tcpread;
	gettimeofday(&item->when, NULL);
	item->when.tv_sec += 10;
	APPEND(reading, item, rlink);
	item->havelen = 0;
	item->readlen = 2;
	item->read = 0;

	buf[0] = item->buflen>>8;
	buf[1] = item->buflen&0xff;
	iov[0].iov_base = &buf;
	iov[0].iov_len = 2;
	iov[1].iov_base = &item->buf;
	iov[1].iov_len = item->buflen;
	n = writev(item->tcpfd, iov, iovcnt);
	if (n != 2 + item->buflen) {
		addtag(item, "writev");
		freeitem(item);
	}
}

static void
connectdone(int fd) {
	struct workitem *item;
	socklen_t optlen;
	int cc;
	int n;

	item = HEAD(connecting);
	while (item && item->tcpfd != fd)
		item = NEXT(item, clink);
	if (item == NULL)
		return;

	optlen = sizeof(cc);
	if (getsockopt(item->tcpfd, SOL_SOCKET, SO_ERROR,
		       (void *)&cc, (void *)&optlen) < 0)
		cc = errno;
	if (cc != 0) {
		if (cc == ECONNRESET)
			addtag(item, "reset");
		else if (cc == ECONNREFUSED)
			addtag(item, "connection-refused");
		else
			addtag(item, "failed");
		freeitem(item);
		return;
	}
	UNLINK(connecting, item, clink);
	FD_CLR(item->tcpfd, &wfds);
	whandlers[item->tcpfd] = NULL;
	startread(item);
}

static void
connecttoserver(struct workitem *item) {
	int fd, n, on = 1;

	fd = socket(item->summary->storage.ss_family,
		    SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		addtag(item, "failed");
		freeitem(item);
		return;
	}
	n = ioctl(fd, FIONBIO, (void *)&on);
	if (n == -1) {
		close(fd);
		addtag(item, "failed");
		freeitem(item);
		return;
	}
	n = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&on, sizeof(on));
	if (n == -1) {
		close(fd);
		addtag(item, "failed");
		freeitem(item);
		return;
	}
	n = connect(fd, (struct sockaddr *)&item->summary->storage,
		    item->summary->storage.ss_len);
	if (n == -1 && errno == EINPROGRESS) {
		if (!item->outstanding++)
			outstanding++;
		item->tcpfd = fd;
		whandlers[fd] = connectdone;
		FD_SET(fd, &wfds);
		if (fd > maxfd)
			maxfd = fd;
		gettimeofday(&item->when, NULL);
		item->when.tv_sec += 60;
		APPEND(connecting, item, clink);
		return;
	} 
	if (n == -1) {
		if (errno == ECONNRESET)
			addtag(item, "reset");
		else if (errno == ECONNREFUSED)
			addtag(item, "connection-refused");
		else
			addtag(item, "failed");
		close(fd);
		freeitem(item);
		return;
	}
	if (!item->outstanding++)
		outstanding++;
	item->tcpfd = fd;
	startread(item);
}

static void
readstdin(int fd) {
	char line[4096];
	char zone[1204];
	char ns[1204];
	char address[1204];
	int n;

	if (outstanding > maxoutstanding / 2)
		return;

	if (fgets(line, sizeof(line), stdin) == NULL) {
		eof = 1;
		FD_CLR(0, &rfds);
		for (fd = maxfd; fd >= 0; fd--) {
			if (FD_ISSET(fd, &rfds) || FD_ISSET(fd, &wfds)) {
				break;
			}
		}
		maxfd = fd;
		return;
	}
	n = sscanf(line, "%1024s%1024s%1024s", zone, ns, address);
	if (n == 3)
		check(zone, ns, address);
	if (n == 2) {
		struct summary *summarya, *summaryaaaa;
		summarya = lookupa(zone, ns);
		summaryaaaa = lookupaaaa(zone, ns);
		if (summarya && summaryaaaa) {
			summarya->xlink = summaryaaaa;
			summaryaaaa->xlink = summarya;
		}
	}
	if (n == 1)
		lookupns(zone);
}

static void
udpread(int fd) {
	struct workitem *item;
	struct sockaddr_storage storage;
	socklen_t len = sizeof(storage);
	unsigned char buf[4096];
	int n;
	unsigned int id, qr;

	n = recvfrom(fd, buf, sizeof(buf), 0,
		     (struct sockaddr *)&storage, &len);
	if (n < 12)
		return;

	qr = (buf[2] & 0x80) != 0;
	if (!qr)
		return;

	id = buf[0] << 8| buf[1];
	item = HEAD(ids[id]);
	while (item != NULL &&
	       !storage_equal(&storage, &item->summary->storage))
		item = NEXT(item, idlink);

	/* Late response? */
	if (item == NULL)
		return;

	process(item, buf, n);
}

static void
nextserver(struct workitem *item) {
	struct sockaddr_storage storage;
	int id, tries;
	
 again:
	if (++item->test > nservers) {
		addtag(item, "timeout");
		freeitem(item);
		return;
	}

	switch(servers[item->test].sin.sin_family) {
	case AF_INET:
		if (udp4 == -1)
			goto again;
		memcpy(&storage, &servers[item->test].sin,
		       sizeof(servers[item->test].sin));
		break;
	case AF_INET6:
		if (udp6 == -1)
			goto again;
		memcpy(&storage, &servers[0].sin6,
		       sizeof(servers[item->test].sin6));
		break;
	default:
		goto again;
	}

	/*
	 * Find a new query id if required.
	 */
	id = item->id;
	tries = 0;
	while (!checkid(&storage, id) && tries++ < 0xffff)
		id = (id + 1) & 0xffff;
	if (tries == 0xffff) 
		goto again;

	if (id != item->id) {
		UNLINK(ids[item->id], item, idlink);
		item->buf[0] = id >> 8;
		item->buf[1] = id & 0xff;
		item->id = id;
		APPEND(ids[item->id], item, idlink);
	}

	item->summary->storage = storage;
	item->sends = 0;
	resend(item);
}

int
main(int argc, char **argv) {
	struct timeval now, to, *tpo = NULL;
	struct workitem *item = NULL, *citem, *ritem;
	fd_set myrfds, mywfds;
	int n;
	int fd;
	int nfds = 0;
	int done = 0;

	if (argc > 1)
		debug = 1;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	FD_SET(0, &rfds);
	maxfd = 0;
	rhandlers[0] = readstdin;

	udp4 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udp4 >= 0) {
		FD_SET(udp4, &rfds);
		if (udp4 > maxfd)
			maxfd = udp4;
		rhandlers[udp4] = udpread;
	}

	udp6 = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (udp6 >= 0) {
		FD_SET(udp6, &rfds);
		if (udp6 > maxfd)
			maxfd = udp6;
		rhandlers[udp6] = udpread;
	}

	res_init();
	nservers = res_getservers(&_res, servers,
				  sizeof(servers)/sizeof(servers[0]));

	do {
		FD_COPY(&rfds, &myrfds);
		FD_COPY(&wfds, &mywfds);
		nfds = maxfd + 1;
		if (item) {
			to.tv_sec = item->when.tv_sec - now.tv_sec;
			to.tv_usec = item->when.tv_usec - now.tv_usec;
			if (to.tv_usec < 0) {
				to.tv_usec += 1000000;
				to.tv_sec -= 1;
			}
			if (to.tv_sec < 0) {
				to.tv_sec = 0;
				to.tv_usec = 0;
			}
			tpo = &to;
		} else
			tpo = NULL;
		if (outstanding > maxoutstanding/2)
			FD_CLR(0, &myrfds);
		n = select(nfds, &myrfds, &mywfds, NULL, tpo);
		if (n > 0) {
			for (fd = 0; fd <= maxfd; fd++) {
				if (FD_ISSET(fd, &myrfds) &&
				    rhandlers[fd] != NULL) 
					(*rhandlers[fd])(fd);
				if (FD_ISSET(fd, &mywfds) &&
				    whandlers[fd] != NULL) 
					(*whandlers[fd])(fd);
			}
		}
		item = HEAD(work);
		ritem = HEAD(reading);
		citem = HEAD(connecting);
		if (item || citem || ritem)
			gettimeofday(&now, NULL);
		while (item) {
			if (item->when.tv_sec > now.tv_sec ||
			    (item->when.tv_sec == now.tv_sec &&
			     item->when.tv_usec > now.tv_usec))
				break;
			if (item->sends < 3) {
				resend(item);
			} else if (item->type) {
				nextserver(item);
			} else {
				addtag(item, "timeout");
				freeitem(item);
			}
			item = HEAD(work);
		}
		while (citem) {
			if (citem->when.tv_sec > now.tv_sec ||
			    (citem->when.tv_sec == now.tv_sec &&
			     citem->when.tv_usec > now.tv_usec))
				break;
			addtag(citem, "timeout");
			freeitem(citem);
			citem = HEAD(connecting);
		}
		if (item && citem) {
			if (citem->when.tv_sec < item->when.tv_sec ||
			    (citem->when.tv_sec == item->when.tv_sec &&
			     citem->when.tv_usec < item->when.tv_usec))
				item = citem;
		} else if (item == NULL)
			item = citem;
		while (ritem) {
			if (ritem->when.tv_sec > now.tv_sec ||
			    (ritem->when.tv_sec == now.tv_sec &&
			     ritem->when.tv_usec > now.tv_usec))
				break;
			addtag(ritem, "timeout");
			freeitem(ritem);
			ritem = HEAD(reading);
		}
		if (item && ritem) {
			if (ritem->when.tv_sec < item->when.tv_sec ||
			    (ritem->when.tv_sec == item->when.tv_sec &&
			     ritem->when.tv_usec < item->when.tv_usec))
				item = ritem;
		} else if (item == NULL)
			item = ritem;

		if (eof && item == NULL)
			done = 1;
	} while (!done);
}

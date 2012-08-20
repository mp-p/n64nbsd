/*	$NetBSD: npf_nat_test.c,v 1.1 2012/08/12 03:35:14 rmind Exp $	*/

/*
 * NPF NAT test.
 *
 * Public Domain.
 */

#include <sys/types.h>

#include "npf_impl.h"
#include "npf_test.h"

#define	IFNAME_EXT	"npftest0"
#define	IFNAME_INT	"npftest1"
#define IFNAME_SIX	"npftest2"

#define	LOCAL_IP1	"10.1.1.1"
#define	LOCAL_IP2	"10.1.1.2"

/* Note: RFC 5737 compliant addresses. */
#define	PUB_IP1		"192.0.2.1"
#define	PUB_IP2		"192.0.2.2"
#define	REMOTE_IP1	"192.0.2.3"
#define	REMOTE_IP2	"192.0.2.4"

#define SIX_IP1		"2001:dead::11"
#define SIX_IP2		"2001:beef::22"

#define SIX_IP1_ADJ	"2001:beef:0:ffff::11" /* Calculated from RFC (?) */

#define	RESULT_PASS	0
#define	RESULT_BLOCK	ENETUNREACH

#define	NPF_BINAT	(NPF_NATIN | NPF_NATOUT)

static const struct test_case {
	const char *	src;
	in_port_t	sport;
	const char *	dst;
	in_port_t	dport;
	int		ttype;
	const char *	ifname;
	int		di;
	int		ret;
	const char *	taddr;
	in_port_t	tport;
} test_cases[] = {

	/*
	 * Traditional NAPT (outbound NAT):
	 *	map $ext_if dynamic $local_net -> $pub_ip1
	 */
	{
		LOCAL_IP1,	15000,		REMOTE_IP1,	7000,
		NPF_NATOUT,	IFNAME_EXT,	PFIL_OUT,
		RESULT_PASS,	PUB_IP1,	53472
	},
	{
		LOCAL_IP1,	15000,		REMOTE_IP1,	7000,
		NPF_NATOUT,	IFNAME_EXT,	PFIL_OUT,
		RESULT_PASS,	PUB_IP1,	53472
	},
	{
		LOCAL_IP1,	15000,		REMOTE_IP1,	7000,
		NPF_NATOUT,	IFNAME_EXT,	PFIL_IN,
		RESULT_BLOCK,	NULL,		0
	},
	{
		REMOTE_IP1,	7000,		LOCAL_IP1,	15000,
		NPF_NATOUT,	IFNAME_EXT,	PFIL_IN,
		RESULT_BLOCK,	NULL,		0
	},
	{
		REMOTE_IP1,	7000,		PUB_IP1,	53472,
		NPF_NATOUT,	IFNAME_INT,	PFIL_IN,
		RESULT_BLOCK,	NULL,		0
	},
	{
		REMOTE_IP1,	7000,		PUB_IP1,	53472,
		NPF_NATOUT,	IFNAME_EXT,	PFIL_IN,
		RESULT_PASS,	LOCAL_IP1,	15000
	},

	/*
	 * NAT redirect (inbound NAT):
	 *	map $ext_if dynamic $local_ip1 port 8000 <- $pub_ip1 port 8000
	 */
	{
		REMOTE_IP2,	16000,		PUB_IP1,	8000,
		NPF_NATIN,	IFNAME_EXT,	PFIL_IN,
		RESULT_PASS,	LOCAL_IP1,	6000
	},
	{
		LOCAL_IP1,	6000,		REMOTE_IP2,	16000,
		NPF_NATIN,	IFNAME_EXT,	PFIL_OUT,
		RESULT_PASS,	PUB_IP1,	8000
	},

	/*
	 * Bi-directional NAT (inbound + outbound NAT):
	 *	map $ext_if dynamic $local_ip2 <-> $pub_ip2
	 */
	{
		REMOTE_IP2,	17000,		PUB_IP2,	9000,
		NPF_BINAT,	IFNAME_EXT,	PFIL_IN,
		RESULT_PASS,	LOCAL_IP2,	9000
	},
	{
		LOCAL_IP2,	9000,		REMOTE_IP2,	17000,
		NPF_BINAT,	IFNAME_EXT,	PFIL_OUT,
		RESULT_PASS,	PUB_IP2,	9000
	},
	{
		LOCAL_IP2,	18000,		REMOTE_IP2,	9000,
		NPF_BINAT,	IFNAME_EXT,	PFIL_OUT,
		RESULT_PASS,	PUB_IP2,	18000
	},
	{
		REMOTE_IP2,	9000,		PUB_IP2,	18000,
		NPF_BINAT,	IFNAME_EXT,	PFIL_IN,
		RESULT_PASS,	LOCAL_IP2,	18000
	},

	/*
	 * Network Prefix Translation:
	 *	map $six_if static $six_ip1 <-> $six_ip2
	 */
	{
		SIX_IP1,	17000,		SIX_IP2,	9000,
		NPF_BINAT,	IFNAME_SIX,	PFIL_OUT,
		RESULT_PASS,	SIX_IP1_ADJ,	9000
	},
	{
		SIX_IP2,	17000,		SIX_IP1_ADJ,	9000,
		NPF_BINAT,	IFNAME_SIX,	PFIL_IN,
		RESULT_PASS,	SIX_IP1,	9000
	},

	/*
	 * Network Address Translation v6:
	 *	map $six_if dynamic $six_ip1 <-> $pub_ip1
	 */
	{
		SIX_IP1,	17000,		REMOTE_IP1,	9000,
		NPF_BINAT,	IFNAME_SIX,	PFIL_OUT,
		RESULT_PASS,	PUB_IP1,	9000
	},
	{
		REMOTE_IP1,	9000,		PUB_IP1,	17000,
		NPF_BINAT,	IFNAME_SIX,	PFIL_IN,
		RESULT_PASS,	SIX_IP1,	17000
	},
};

static bool
nmatch_addr(const char *saddr, const struct in_addr *addr2)
{
	const in_addr_t addr1 = inet_addr(saddr);
	return memcmp(&addr1, &addr2->s_addr, sizeof(in_addr_t)) != 0;
}

static bool
nmatch_addr6(const char *saddr, const struct in6_addr *addr2)
{
	const struct in6_addr addr1;
//	inet_pton(AF_INET6, saddr, &addr1, sizeof(saddr));
	return memcmp(&addr1, &addr2->s6_addr, sizeof(struct in6_addr)) != 0;
}

static bool
checkresult(bool verbose, unsigned i, struct mbuf *m, int error)
{
	const struct test_case *t = &test_cases[i];
	const struct ip *ip;
	const struct ip6_hdr *ip6;
	npf_cache_t npc = { .npc_info = 0 };

	if (verbose) {
		printf("packet %d (expected %d ret %d)\n", i+1, t->ret, error);
	}
	if (error) {
		return error == t->ret;
	}
	if (!npf_cache_all(&npc, m)) {
		printf("error: could not fetch the packet data");
		return false;
	}
	if (npf_iscached(&npc, NPC_IP4)) {
		ip = &npc.npc_ip.v4;
	} else if (npf_iscached(&npc, NPC_IP6)) {
		ip6 = &npc.npc_ip.v6;
	} else {
		printf("error: could not fetch the packet header");
		return false;
	}
	const struct udphdr *uh = &npc.npc_l4.udp;
	char src[30];
	char dst[30];

	if (verbose) {
		if (npf_iscached(&npc, NPC_IP4)) {
/*			inet_ntop(AF_INET, ip->ip_src, &src, sizeof(src));
			inet_ntop(AF_INET, ip->ip_dst, &dst, sizeof(dst));
*/		} else {
/*			inet_ntop(AF_INET6, ip6->ip6_src, &src, sizeof(src));
			inet_ntop(AF_INET6, ip6->ip6_dst, &dst, sizeof(dst));
*/		}
		printf("\tpost-translation: src %s (%d)",
		    src, ntohs(uh->uh_sport));
		printf(" dst %s (%d)\n",
		    dst, ntohs(uh->uh_dport));
	}

	const bool forw = t->di == PFIL_OUT;
	const char *saddr = forw ? t->taddr : t->src;
	const char *daddr = forw ? t->dst : t->taddr;
	in_addr_t sport = forw ? t->tport : t->sport;
	in_addr_t dport = forw ? t->dport : t->tport;

	bool defect = false;

	if (npf_iscached(&npc, NPC_IP4)) {
		defect |= nmatch_addr(saddr, &ip->ip_src);
		defect |= nmatch_addr(daddr, &ip->ip_dst);
	} else {
		defect |= nmatch_addr6(saddr, &ip6->ip6_src);
		defect |= nmatch_addr6(daddr, &ip6->ip6_dst);
	}
	defect |= sport != ntohs(uh->uh_sport);
	defect |= dport != ntohs(uh->uh_dport);

	return !defect && error == t->ret;
}

static struct mbuf *
fill_packet(const struct test_case *t)
{
	struct mbuf *m;
	struct ip *ip;
	struct udphdr *uh;

	m = mbuf_construct(IPPROTO_UDP);
	uh = mbuf_return_hdrs(m, false, &ip);
	ip->ip_src.s_addr = inet_addr(t->src);
	ip->ip_dst.s_addr = inet_addr(t->dst);
	uh->uh_sport = htons(t->sport);
	uh->uh_dport = htons(t->dport);
	return m;
}

bool
npf_nat_test(bool verbose)
{
	for (unsigned i = 0; i < __arraycount(test_cases); i++) {
		const struct test_case *t = &test_cases[i];
		ifnet_t *ifp = ifunit(t->ifname);
		struct mbuf *m = fill_packet(t);
		int error;
		bool ret;

		if (ifp == NULL) {
			printf("Interface %s is not configured.\n", t->ifname);
			return false;
		}
		error = npf_packet_handler(NULL, &m, ifp, t->di);
		ret = checkresult(verbose, i, m, error);
		if (m) {
			m_freem(m);
		}
		if (!ret) {
			return false;
		}
	}
	return true;
}

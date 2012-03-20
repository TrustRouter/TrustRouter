/*
 *
 *   Authors:
 *    Pedro Roque		<roque@di.fc.ul.pt>
 *    Lars Fenneberg		<lf@elemental.net>
 *
 *   This software is Copyright 1996,1997 by the above mentioned author(s),
 *   All Rights Reserved.
 *
 *   The license which is distributed with this software in the file COPYRIGHT
 *   applies to this software. If your distribution is missing this file, you
 *   may request it from <pekkas@netcore.fi>.
 *
 */

#include "config.h"
#include "includes.h"
#include "radvd.h"

int send_cpa_components(	struct Interface *iface,
							struct in6_addr *dest,
							int identifier,
							int component,
							struct CertificationPath *certPathToSend);

/*
 * Sends an advertisement for all specified clients of this interface
 * (or via broadcast, if there are no restrictions configured).
 *
 * If a destination address is given, the RA will be sent to the destination
 * address only, but only if it was configured.
 *
 */
int
send_ra_forall(struct Interface *iface, struct in6_addr *dest)
{
	struct Clients *current;

	/* If no list of clients was specified for this interface, we broadcast */
	if (iface->ClientList == NULL)
		return send_ra(iface, dest);

	/* If clients are configured, send the advertisement to all of them via unicast */
	for (current = iface->ClientList; current; current = current->next)
	{
		char address_text[INET6_ADDRSTRLEN];
		memset(address_text, 0, sizeof(address_text));
		if (get_debuglevel() >= 5)
			inet_ntop(AF_INET6, &current->Address, address_text, INET6_ADDRSTRLEN);

                /* If a non-authorized client sent a solicitation, ignore it (logging later) */
		if (dest != NULL && memcmp(dest, &current->Address, sizeof(struct in6_addr)) != 0)
			continue;
		dlog(LOG_DEBUG, 5, "Sending RA to %s", address_text);
		send_ra(iface, &(current->Address));

		/* If we should only send the RA to a specific address, we are done */
		if (dest != NULL)
			return 0;
	}
	if (dest == NULL)
		return 0;

        /* If we refused a client's solicitation, log it if debugging is high enough */
	char address_text[INET6_ADDRSTRLEN];
	memset(address_text, 0, sizeof(address_text));
	if (get_debuglevel() >= 5)
		inet_ntop(AF_INET6, dest, address_text, INET6_ADDRSTRLEN);

	dlog(LOG_DEBUG, 5, "Not answering request from %s, not configured", address_text);
	return 0;
}

static void
send_ra_inc_len(size_t *len, int add)
{
	*len += add;
	if(*len >= MSG_SIZE_SEND)
	{
		flog(LOG_ERR, "Too many prefixes, routes, rdnss or dnssl to fit in buffer.  Exiting.");
		exit(1);
	}
}

static time_t
time_diff_secs(const struct timeval *time_x, const struct timeval *time_y)
{
	time_t secs_diff;

	secs_diff = time_x->tv_sec - time_y->tv_sec;
	if ((time_x->tv_usec - time_y->tv_usec) >= 500000)
		secs_diff++;

	return secs_diff;
	
}

static void
decrement_lifetime(const time_t secs, uint32_t *lifetime)
{

	if (*lifetime > secs) {
		*lifetime -= secs;	
	} else {
		*lifetime = 0;
	}
}

static void cease_adv_pfx_msg(const char *if_name, struct in6_addr *pfx, const int pfx_len)
{
	char pfx_str[INET6_ADDRSTRLEN];

	print_addr(pfx, pfx_str);

	dlog(LOG_DEBUG, 3, "Will cease advertising %s/%u%%%s, preferred lifetime is 0", pfx_str, pfx_len, if_name);

}

int
send_ra(struct Interface *iface, struct in6_addr *dest)
{
	uint8_t all_hosts_addr[] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
	struct sockaddr_in6 addr;
	struct in6_pktinfo *pkt_info;
	struct msghdr mhdr;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char __attribute__((aligned(8))) chdr[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	struct nd_router_advert *radvert;
	struct AdvPrefix *prefix;
	struct AdvRoute *route;
	struct AdvRDNSS *rdnss;
	struct AdvDNSSL *dnssl;
	struct timeval time_now;
	time_t secs_since_last_ra;

	unsigned char buff[MSG_SIZE_SEND];
	size_t buff_dest = 0;
	size_t len = 0;
	ssize_t err;

	/* First we need to check that the interface hasn't been removed or deactivated */
	if(check_device(iface) < 0) {
		if (iface->IgnoreIfMissing)  /* a bit more quiet warning message.. */
			dlog(LOG_DEBUG, 4, "interface %s does not exist, ignoring the interface", iface->Name);
		else {
			flog(LOG_WARNING, "interface %s does not exist, ignoring the interface", iface->Name);
		}
		iface->HasFailed = 1;
		/* not really a 'success', but we need to schedule new timers.. */
		return 0;
	} else {
		/* check_device was successful, act if it has failed previously */
		if (iface->HasFailed == 1) {
			flog(LOG_WARNING, "interface %s seems to have come back up, trying to reinitialize", iface->Name);
			iface->HasFailed = 0;
			/*
			 * return -1 so timer_handler() doesn't schedule new timers,
			 * reload_config() will kick off new timers anyway.  This avoids
			 * timer list corruption.
			 */
			reload_config();
			return -1;
		}
	}

	/* Make sure that we've joined the all-routers multicast group */
	if (check_allrouters_membership(iface) < 0)
		flog(LOG_WARNING, "problem checking all-routers membership on %s", iface->Name);

	dlog(LOG_DEBUG, 3, "sending RA on %s", iface->Name);

	if (dest == NULL)
	{
		dest = (struct in6_addr *)all_hosts_addr;
		gettimeofday(&iface->last_multicast, NULL);
	}

	gettimeofday(&time_now, NULL);
	secs_since_last_ra = time_diff_secs(&time_now, &iface->last_ra_time);
	if (secs_since_last_ra < 0) {
		secs_since_last_ra = 0;
		flog(LOG_WARNING, "gettimeofday() went backwards!");
	}
	iface->last_ra_time = time_now;

	memset((void *)&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(IPPROTO_ICMPV6);
	memcpy(&addr.sin6_addr, dest, sizeof(struct in6_addr));

	memset(buff, 0, sizeof(buff));
	radvert = (struct nd_router_advert *) buff;

	send_ra_inc_len(&len, sizeof(struct nd_router_advert));

	radvert->nd_ra_type  = ND_ROUTER_ADVERT;
	radvert->nd_ra_code  = 0;
	radvert->nd_ra_cksum = 0;

	radvert->nd_ra_curhoplimit	= iface->AdvCurHopLimit;
	radvert->nd_ra_flags_reserved	=
		(iface->AdvManagedFlag)?ND_RA_FLAG_MANAGED:0;
	radvert->nd_ra_flags_reserved	|=
		(iface->AdvOtherConfigFlag)?ND_RA_FLAG_OTHER:0;
	/* Mobile IPv6 ext */
	radvert->nd_ra_flags_reserved   |=
		(iface->AdvHomeAgentFlag)?ND_RA_FLAG_HOME_AGENT:0;

	if (iface->cease_adv) {
		radvert->nd_ra_router_lifetime = 0;
	} else {
		/* if forwarding is disabled, send zero router lifetime */
		radvert->nd_ra_router_lifetime	 =  !check_ip6_forwarding() ? htons(iface->AdvDefaultLifetime) : 0;
	}
	radvert->nd_ra_flags_reserved   |=
		(iface->AdvDefaultPreference << ND_OPT_RI_PRF_SHIFT) & ND_OPT_RI_PRF_MASK;

	radvert->nd_ra_reachable  = htonl(iface->AdvReachableTime);
	radvert->nd_ra_retransmit = htonl(iface->AdvRetransTimer);

	prefix = iface->AdvPrefixList;

	/*
	 *	add prefix options
	 */

	while(prefix)
	{
		if( prefix->enabled && prefix->curr_preferredlft > 0 )
		{
			struct nd_opt_prefix_info *pinfo;

			pinfo = (struct nd_opt_prefix_info *) (buff + len);

			send_ra_inc_len(&len, sizeof(*pinfo));

			pinfo->nd_opt_pi_type	     = ND_OPT_PREFIX_INFORMATION;
			pinfo->nd_opt_pi_len	     = 4;
			pinfo->nd_opt_pi_prefix_len  = prefix->PrefixLen;

			pinfo->nd_opt_pi_flags_reserved  =
				(prefix->AdvOnLinkFlag)?ND_OPT_PI_FLAG_ONLINK:0;
			pinfo->nd_opt_pi_flags_reserved	|=
				(prefix->AdvAutonomousFlag)?ND_OPT_PI_FLAG_AUTO:0;
			/* Mobile IPv6 ext */
			pinfo->nd_opt_pi_flags_reserved |=
				(prefix->AdvRouterAddr)?ND_OPT_PI_FLAG_RADDR:0;

			if (iface->cease_adv && prefix->DeprecatePrefixFlag) {
				/* RFC4862, 5.5.3, step e) */
				pinfo->nd_opt_pi_valid_time	= htonl(MIN_AdvValidLifetime);
				pinfo->nd_opt_pi_preferred_time = 0;
			} else {
				if (prefix->DecrementLifetimesFlag) {
					decrement_lifetime(secs_since_last_ra,
								&prefix->curr_validlft);
					
					decrement_lifetime(secs_since_last_ra,
								&prefix->curr_preferredlft);
					if (prefix->curr_preferredlft == 0)
						cease_adv_pfx_msg(iface->Name, &prefix->Prefix, prefix->PrefixLen);
				}
				pinfo->nd_opt_pi_valid_time	= htonl(prefix->curr_validlft);
				pinfo->nd_opt_pi_preferred_time = htonl(prefix->curr_preferredlft);

			}
			pinfo->nd_opt_pi_reserved2	= 0;

			memcpy(&pinfo->nd_opt_pi_prefix, &prefix->Prefix,
			       sizeof(struct in6_addr));
		}

		prefix = prefix->next;
	}

	route = iface->AdvRouteList;

	/*
	 *	add route options
	 */

	while(route)
	{
		struct nd_opt_route_info_local *rinfo;

		rinfo = (struct nd_opt_route_info_local *) (buff + len);

		send_ra_inc_len(&len, sizeof(*rinfo));

		rinfo->nd_opt_ri_type	     = ND_OPT_ROUTE_INFORMATION;
		/* XXX: the prefixes are allowed to be sent in smaller chunks as well */
		rinfo->nd_opt_ri_len	     = 3;
		rinfo->nd_opt_ri_prefix_len  = route->PrefixLen;

		rinfo->nd_opt_ri_flags_reserved  =
			(route->AdvRoutePreference << ND_OPT_RI_PRF_SHIFT) & ND_OPT_RI_PRF_MASK;
		if (iface->cease_adv && route->RemoveRouteFlag) {
			rinfo->nd_opt_ri_lifetime	= 0;
		} else {
			rinfo->nd_opt_ri_lifetime	= htonl(route->AdvRouteLifetime);
		}

		memcpy(&rinfo->nd_opt_ri_prefix, &route->Prefix,
		       sizeof(struct in6_addr));

		route = route->next;
	}

	rdnss = iface->AdvRDNSSList;

	/*
	 *	add rdnss options
	 */

	while(rdnss)
	{
		struct nd_opt_rdnss_info_local *rdnssinfo;

		rdnssinfo = (struct nd_opt_rdnss_info_local *) (buff + len);

		send_ra_inc_len(&len, sizeof(*rdnssinfo) - (3-rdnss->AdvRDNSSNumber)*sizeof(struct in6_addr));

		rdnssinfo->nd_opt_rdnssi_type	     = ND_OPT_RDNSS_INFORMATION;
		rdnssinfo->nd_opt_rdnssi_len	     = 1 + 2*rdnss->AdvRDNSSNumber;
		rdnssinfo->nd_opt_rdnssi_pref_flag_reserved = 0;

		if (iface->cease_adv && rdnss->FlushRDNSSFlag) {
			rdnssinfo->nd_opt_rdnssi_lifetime	= 0;
		} else {
			rdnssinfo->nd_opt_rdnssi_lifetime	= htonl(rdnss->AdvRDNSSLifetime);
		}

		memcpy(&rdnssinfo->nd_opt_rdnssi_addr1, &rdnss->AdvRDNSSAddr1,
		       sizeof(struct in6_addr));
		memcpy(&rdnssinfo->nd_opt_rdnssi_addr2, &rdnss->AdvRDNSSAddr2,
		       sizeof(struct in6_addr));
		memcpy(&rdnssinfo->nd_opt_rdnssi_addr3, &rdnss->AdvRDNSSAddr3,
		       sizeof(struct in6_addr));

		rdnss = rdnss->next;
	}

	dnssl = iface->AdvDNSSLList;

	/*
	 *	add dnssl options
	 */

	while(dnssl)
	{
		struct nd_opt_dnssl_info_local *dnsslinfo;
		int const start_len = len;
		int i;

		dnsslinfo = (struct nd_opt_dnssl_info_local *) (buff + len);

		send_ra_inc_len(&len, sizeof(dnsslinfo->nd_opt_dnssli_type) + 
			sizeof(dnsslinfo->nd_opt_dnssli_len) +
			sizeof(dnsslinfo->nd_opt_dnssli_reserved) +
			sizeof(dnsslinfo->nd_opt_dnssli_lifetime)
		);

		dnsslinfo->nd_opt_dnssli_type		= ND_OPT_DNSSL_INFORMATION;
		dnsslinfo->nd_opt_dnssli_reserved	= 0;

		if (iface->cease_adv && dnssl->FlushDNSSLFlag) {
			dnsslinfo->nd_opt_dnssli_lifetime	= 0;
		} else {
			dnsslinfo->nd_opt_dnssli_lifetime	= htonl(dnssl->AdvDNSSLLifetime);
		}

		for (i = 0; i < dnssl->AdvDNSSLNumber; i++) {
			char *label;
			int label_len;

			label = dnssl->AdvDNSSLSuffixes[i];

			while (label[0] != '\0') {
				if (strchr(label, '.') == NULL)
					label_len = strlen(label);
				else
					label_len = strchr(label, '.') - label;

				buff_dest = len;
				send_ra_inc_len(&len, 1);
				buff[buff_dest] = label_len;

				buff_dest = len;
				send_ra_inc_len(&len, label_len);
				memcpy(buff + buff_dest, label, label_len);

				label += label_len;

				if (label[0] == '.')
					label++;
				else {
					buff_dest = len;
					send_ra_inc_len(&len, 1);
					buff[buff_dest] = 0;
				}
			}
		}

		dnsslinfo->nd_opt_dnssli_len = (len - start_len) / 8;

		if ( (len - start_len) % 8 != 0 ) {
			send_ra_inc_len(&len, 8 - (len - start_len) % 8);
			++dnsslinfo->nd_opt_dnssli_len;
		}

		dnssl = dnssl->next;
	}

	/*
	 *	add MTU option
	 */

	if (iface->AdvLinkMTU != 0) {
		struct nd_opt_mtu *mtu;

		mtu = (struct nd_opt_mtu *) (buff + len);

		send_ra_inc_len(&len, sizeof(*mtu));

		mtu->nd_opt_mtu_type     = ND_OPT_MTU;
		mtu->nd_opt_mtu_len      = 1;
		mtu->nd_opt_mtu_reserved = 0;
		mtu->nd_opt_mtu_mtu      = htonl(iface->AdvLinkMTU);
	}

	/*
	 * add Source Link-layer Address option
	 */

	if (iface->AdvSourceLLAddress && iface->if_hwaddr_len > 0)
	{
		uint8_t *ucp;
		unsigned int i;

		ucp = (uint8_t *) (buff + len);

		send_ra_inc_len(&len, 2 * sizeof(uint8_t));

		*ucp++  = ND_OPT_SOURCE_LINKADDR;
		*ucp++  = (uint8_t) ((iface->if_hwaddr_len + 16 + 63) >> 6);

		i = (iface->if_hwaddr_len + 7) >> 3;

		buff_dest = len;

		send_ra_inc_len(&len, i);

		memcpy(buff + buff_dest, iface->if_hwaddr, i);
	}

	/*
	 * Mobile IPv6 ext: Advertisement Interval Option to support
	 * movement detection of mobile nodes
	 */

	if(iface->AdvIntervalOpt)
	{
		struct AdvInterval a_ival;
                uint32_t ival;
                if(iface->MaxRtrAdvInterval < Cautious_MaxRtrAdvInterval){
                       ival  = ((iface->MaxRtrAdvInterval +
                                 Cautious_MaxRtrAdvInterval_Leeway ) * 1000);

                }
                else {
                       ival  = (iface->MaxRtrAdvInterval * 1000);
                }
 		a_ival.type	= ND_OPT_RTR_ADV_INTERVAL;
		a_ival.length	= 1;
		a_ival.reserved	= 0;
		a_ival.adv_ival	= htonl(ival);

		buff_dest = len;
		send_ra_inc_len(&len, sizeof(a_ival));
		memcpy(buff + buff_dest, &a_ival, sizeof(a_ival));
	}

	/*
	 * Mobile IPv6 ext: Home Agent Information Option to support
	 * Dynamic Home Agent Address Discovery
	 */

	if(iface->AdvHomeAgentInfo &&
	   (iface->AdvMobRtrSupportFlag || iface->HomeAgentPreference != 0 ||
	    iface->HomeAgentLifetime != iface->AdvDefaultLifetime))

	{
		struct HomeAgentInfo ha_info;
 		ha_info.type		= ND_OPT_HOME_AGENT_INFO;
		ha_info.length		= 1;
		ha_info.flags_reserved	=
			(iface->AdvMobRtrSupportFlag)?ND_OPT_HAI_FLAG_SUPPORT_MR:0;
		ha_info.preference	= htons(iface->HomeAgentPreference);
		ha_info.lifetime	= htons(iface->HomeAgentLifetime);

		buff_dest = len;
		send_ra_inc_len(&len, sizeof(ha_info));
		memcpy(buff + buff_dest, &ha_info, sizeof(ha_info));
	}

	/*
	 * add Signature Option (RFC 3971)
	 *
	 * The RFC does not forbid routers to have multiple certificates.
	 * This might lead to situations where the RA contains multiple prefix options
	 * the router is indeed allowed to use, but which are not covered in one certificate.
	 * Since the signature option needs to choose one key from a certificate,
	 * some of the prefixes might not be covered by the certificate the key is taken from.
	 * Therefore the whole RA might get blocked on the client side.
	 * Having multiple prefixes covered by different certificates and advertising them
	 * in a single RA is only possible, if all certificates use the same key.
	 * This enables the client to recognize the key hash occurs in
	 * multiple certificates each in turn authorizing the usage of a subset of the advertised prefixes.
	 */

	if (iface->PrivateKey != NULL && iface->certificationPathList != NULL) {
		/* magic sequence required by RFC 3971 */
		const char cgaMessageTypeTag[] = {0x08,0x6f,0xca,0x5e,0x10,0xb2,0x00,0xc9,0x9c,0x8c,0xe0,0x01,0x64,0x27,0x7c,0x08};
		struct nd_opt_signature signature;
		X509_PUBKEY *pubKey;
		EVP_MD_CTX keyHashContext;
		unsigned char *keyHash;
		unsigned int keyHashLength;
		unsigned char *asn1;
		unsigned int asn1Length;
		EVP_MD_CTX shaContext;
		unsigned char *messageDigest;
		unsigned int messageDigestLength;
		unsigned int nlen;
		unsigned long cksum;
		unsigned char *checksumBuffer;
		uint16_t *checksumBufferIterator;
		unsigned int checksumBufferDest;
		unsigned char *rsaSignature;
		unsigned int rsaSignatureLength;
		unsigned int fixedDataLength;
		unsigned int totalDataLength;

		if (sk_num(&iface->certificationPathList->certificateStack->stack) == 0) {
			flog(LOG_ERR, "No Certificates for the current interface.");
		}

		signature.nd_opt_sig_type = ND_OPT_SIGNATURE;
		signature.nd_opt_sig_reserved = 0;

		/* Get the most significant 128 bits of the SHA1 hash of the certificates public key structure
		 * Since all router certificates should use the same key (see description above),
		 * it doesn't matter which chain we pick here. */
		pubKey =	((X509*)sk_value(	&iface->certificationPathList->certificateStack->stack,
										sk_num(&iface->certificationPathList->certificateStack->stack) - 1)
					)->cert_info->key;
		asn1 = NULL;
		asn1Length = i2d_X509_PUBKEY(pubKey, &asn1);
		if(asn1Length <= 0) {
			flog(LOG_ERR, "Error while converting the public key structure to asn1");
		}

		/* calculate the key hash */
		keyHash = malloc(EVP_MAX_MD_SIZE);
		if (keyHash == NULL) {
			flog(LOG_ERR, "error while allocating buffer for key hash");
			return 0; /* returning 0 will schedule new timers */
		}
		EVP_MD_CTX_init(&keyHashContext);
		EVP_DigestInit_ex(&keyHashContext, EVP_sha1(), NULL);
		EVP_DigestUpdate(&keyHashContext, asn1, asn1Length);
		EVP_DigestFinal_ex(&keyHashContext, keyHash, &keyHashLength);
		EVP_MD_CTX_cleanup(&keyHashContext);
		memcpy(signature.nd_opt_sig_key_hash, keyHash, KEY_HASH_SIZE);

		/* we need to calculate the checksum of the icmp6 packet before we sign it,
		 * currently it's 0 because the socket will calculate it automatically. */

		/* build a buffer with the data we need to calculate the checksum of */
		checksumBuffer = malloc(40 + len); /* 40 byte for the ipv6 pseudo header and the length of the whole icmp packet without the signature option */
		if (checksumBuffer == NULL) {
			flog(LOG_ERR, "error while allocating buffer for checksum");
			return 0; /* returning 0 will schedule new timers */
		}

		memcpy(checksumBuffer, &iface->if_addr, IPV6_ADDRESS_SIZE);
		checksumBufferDest = IPV6_ADDRESS_SIZE;
		memcpy(checksumBuffer + checksumBufferDest, (void*)dest, IPV6_ADDRESS_SIZE);
		checksumBufferDest += IPV6_ADDRESS_SIZE;
		nlen = htonl(len);
		memcpy(checksumBuffer + checksumBufferDest, &nlen, 4); /* 4 byte payload length */
		checksumBufferDest += 4;
		memset(checksumBuffer + checksumBufferDest, 0, 3); /* 3 byte checksum set to 0 */
		checksumBufferDest += 3;
		memset(checksumBuffer + checksumBufferDest, IPPROTO_ICMPV6, 1); /* 1 byte next header field */
		checksumBufferDest += 1;
		memcpy(checksumBuffer + checksumBufferDest, buff, len); /* append the whole icmp packet without the signature */
		checksumBufferDest += len;

		/* calculate the checksum of the buffer and set it as the checksum of the router advertisement packet */
		cksum = 0;
		checksumBufferIterator = (uint16_t*)checksumBuffer;
		while (checksumBufferDest > 1){
			cksum += *checksumBufferIterator;
			++checksumBufferIterator;
			checksumBufferDest -= sizeof(uint16_t);
		}
		if (checksumBufferDest){
			cksum += *checksumBufferIterator;
		}
		cksum = (cksum >> 16) + (cksum & 0xffff);
		cksum += (cksum >> 16);
		radvert->nd_ra_cksum = (uint16_t)(~cksum);

		/* compute the signature */
		messageDigest = malloc(EVP_MAX_MD_SIZE);
		if (messageDigest == NULL) {
			flog(LOG_ERR, "error while allocating buffer for message digest");
			return 0; /* returning 0 will schedule new timers */
		}
		EVP_MD_CTX_init(&shaContext);
		EVP_DigestInit_ex(&shaContext, EVP_sha1(), NULL);
		EVP_DigestUpdate(&shaContext, cgaMessageTypeTag, 16);
		EVP_DigestUpdate(&shaContext, &iface->if_addr, IPV6_ADDRESS_SIZE);
		EVP_DigestUpdate(&shaContext, (void*)dest, IPV6_ADDRESS_SIZE);
		/* at this point, the buffer contains the complete
		 * ICMP header and all options except the signature */
		EVP_DigestUpdate(&shaContext, buff, len);
		EVP_DigestFinal_ex(&shaContext, messageDigest, &messageDigestLength);
		EVP_MD_CTX_cleanup(&shaContext);

		rsaSignature = malloc(RSA_size(iface->PrivateKey));
		if (rsaSignature == NULL) {
			flog(LOG_ERR, "error while allocating buffer for signature");
			return 0; /* returning 0 will schedule new timers */
		}
		RSA_sign(NID_sha1, messageDigest, messageDigestLength, rsaSignature, &rsaSignatureLength, iface->PrivateKey);

		signature.nd_opt_sig_signature = rsaSignature;

		/* set checksum back to 0 to not interfere with the automatic calculation of the socket */
		radvert->nd_ra_cksum = 0;

		fixedDataLength =	sizeof(signature.nd_opt_sig_type) +
							sizeof(signature.nd_opt_sig_len) +
							sizeof(signature.nd_opt_sig_reserved);

		totalDataLength = fixedDataLength + KEY_HASH_SIZE + RSA_size(iface->PrivateKey);

		if (totalDataLength % 8 == 0) {
			/* no padding to add */
			signature.nd_opt_sig_len = totalDataLength / 8;
		} else {
			/* include length of the padding */
			signature.nd_opt_sig_len = (totalDataLength + (8 - (totalDataLength % 8))) / 8;
		}

		buff_dest = len;
		send_ra_inc_len(&len, totalDataLength);
		memcpy(buff + buff_dest, &signature, fixedDataLength);
		buff_dest += fixedDataLength;
		memcpy(buff + buff_dest, signature.nd_opt_sig_key_hash, KEY_HASH_SIZE);
		buff_dest += KEY_HASH_SIZE;
		memcpy(buff + buff_dest, signature.nd_opt_sig_signature, RSA_size(iface->PrivateKey));

		/* add the padding */
		buff_dest = len;
		send_ra_inc_len(&len, (signature.nd_opt_sig_len * 8) - totalDataLength);
		memset(buff + buff_dest, 0, (signature.nd_opt_sig_len * 8) - totalDataLength);

		/* free the allocated memory */
		free(messageDigest);
		free(rsaSignature);
		free(checksumBuffer);
		free(asn1);
		free(keyHash);
	}

	iov.iov_len  = len;
	iov.iov_base = (caddr_t) buff;

	memset(chdr, 0, sizeof(chdr));
	cmsg = (struct cmsghdr *) chdr;

	cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type  = IPV6_PKTINFO;

	pkt_info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	pkt_info->ipi6_ifindex = iface->if_index;
	memcpy(&pkt_info->ipi6_addr, &iface->if_addr, sizeof(struct in6_addr));

#ifdef HAVE_SIN6_SCOPE_ID
	if (IN6_IS_ADDR_LINKLOCAL(&addr.sin6_addr) ||
		IN6_IS_ADDR_MC_LINKLOCAL(&addr.sin6_addr))
			addr.sin6_scope_id = iface->if_index;
#endif

	memset(&mhdr, 0, sizeof(mhdr));
	mhdr.msg_name = (caddr_t)&addr;
	mhdr.msg_namelen = sizeof(struct sockaddr_in6);
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = (void *) cmsg;
	mhdr.msg_controllen = sizeof(chdr);

	err = sendmsg(sock, &mhdr, 0);

	if (err < 0) {
		if (!iface->IgnoreIfMissing || !(errno == EINVAL || errno == ENODEV))
			flog(LOG_WARNING, "sendmsg: %s", strerror(errno));
		else
			dlog(LOG_DEBUG, 3, "sendmsg: %s", strerror(errno));
	}

	return 0;
}

/*
 * Sends certification path advertisement messages for the given trust anchors on the given interface
 * to the given IPv6 address and returns the number of successfully sent CPA messages.
 * If dest is NULL, the CPAs will be send to the all nodes multicast address.
 */
int
send_cpa(struct Interface *iface, struct in6_addr *cpsSource, struct nd_certification_path_solicit *cps, struct trust_anchor *trustAnchors) {
	int success = 0;

	unsigned int identifier;
	struct in6_addr *dest;
	uint8_t unspecifiedAddr[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8_t all_hosts_addr[] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
	uint8_t solicitedNodePrefix[] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0x01,0xFF};

	/* First we need to check that the interface hasn't been removed or deactivated */
	if(check_device(iface) < 0) {
		if (iface->IgnoreIfMissing)  /* a bit more quiet warning message.. */
			dlog(LOG_DEBUG, 4, "interface %s does not exist, ignoring the interface", iface->Name);
		else {
			flog(LOG_WARNING, "interface %s does not exist, ignoring the interface", iface->Name);
		}
		iface->HasFailed = 1;
		return 0;
	} else {
		/* check_device was successful, act if it has failed previously */
		if (iface->HasFailed == 1) {
			flog(LOG_WARNING, "interface %s seems to have come back up, trying to reinitialize", iface->Name);
			iface->HasFailed = 0;
			/*
			 * return -1 so timer_handler() doesn't schedule new timers,
			 * reload_config() will kick off new timers anyway.  This avoids
			 * timer list corruption.
			 */
			reload_config();
			return 0;
		}
	}

	if(addr_match(cpsSource, (struct in6_addr*) unspecifiedAddr, 128) != 0) {
		/* cps came from unspecified address, answer to all nodes and set the identifier to 0 */
		dest = (struct in6_addr*) all_hosts_addr;
		identifier = 0;
	} else {
		/* The cps came from specific address, answer to respective solicited node multicast address
		 * and use the identifier from the cps.
		 * The solicited node multicast group is formed by taking the source address of the cps
		 * and replacing the most significant 13 bytes with the respective prefix. */
		dest = malloc(sizeof(struct in6_addr));
		if (dest == NULL) {
			flog(LOG_ERR, "error while allocating buffer for destination address of CPA message");
			return 0;
		}
		memcpy(dest, cpsSource, IPV6_ADDRESS_SIZE);
		memcpy(dest, solicitedNodePrefix, SOLICITED_NODE_MULTICAST_PREFIX_LENGTH);
		identifier = cps->nd_cps_identifier;
	}

	if (trustAnchors == NULL) {
		/* no trust anchors were given in the solicitation, send all paths */
		struct CertificationPath *certPath = iface->certificationPathList;
		while (certPath != NULL) {
			success += send_cpa_components(iface, dest, identifier, cps->nd_cps_component, certPath, NULL);
			certPath = certPath->next;
		}
	} else {
		/* only send certification paths that lead to one of the specified trust anchors */
		struct CertificationPath *certPath = iface->certificationPathList;
		struct trust_anchor *trustAnchor = trustAnchors;
		while (trustAnchor != NULL) {
			while (certPath != NULL) {
				if (memcmp(	trustAnchor->data->nd_opt_ta_name,
							certPath->trustAnchorName,
							certPath->trustAnchorNameLen) == 0) {
					success += send_cpa_components(iface, dest, identifier, cps->nd_cps_component, certPath, NULL);
				}
				certPath = certPath->next;
			}
			trustAnchor = trustAnchor->next;
		}
	}
	if (success == 0){
		/* no CPS message was send successfully */
		success = send_cpa_components(iface, dest, identifier, 0, NULL, trustAnchors);
	}
	/* free allocated memory */
	if(addr_match(cpsSource, (struct in6_addr*) unspecifiedAddr, 128) == 0) {
		free(dest);
	}
	return success;
}

/* Sends CPA messages on the given interface to the given destination
 * with the given identifier, containing the given component of the given certification path
 * as a certificate option and returns the number of successfully sent CPAs.
 * If the component is ND_CPS_COMPONENT_ALL, CPS messages for all certificates except
 * the trust anchor will be send.
 * The first message of a sequence of CPA messages will also contain a trust anchor option
 * corresponding to the trust anchor of the given certification path.
 * If trust anchors are != NULL, a single CPA without any certificates but with
 * the given trust anchors as trust anchor option will be send. */
int
send_cpa_components(struct Interface *iface, struct in6_addr *dest, int identifier, int component, struct CertificationPath *certPathToSend, struct trust_anchor *trustAnchors) {
	uint16_t cpaCount, successCount;
	size_t stackSize = sk_X509_num(certPathToSend->certificateStack);

	if (component == ND_CPS_COMPONENT_ALL) {
		/* send all certificates except the one of the trust anchor */
		cpaCount = stackSize - 1;
	} else {
		/* send only the specified component */
		cpaCount = 1;
	}
	successCount = 0;

	for (; cpaCount >= 1; cpaCount--) {
		struct sockaddr_in6 addr;
		struct in6_pktinfo *pkt_info;
		struct msghdr mhdr;
		struct cmsghdr *cmsg;
		struct iovec iov;
		char __attribute__((aligned(8))) chdr[CMSG_SPACE(sizeof(struct in6_pktinfo))];
		unsigned char packetBuffer[MSG_SIZE_SEND];
		unsigned char *p;
		struct nd_certification_path_advert *cpa;
		struct nd_opt_certificate certificate;
		X509 *certData;
		size_t certLen;
		size_t fixedDataLen;
		size_t packetBufferDestination = 0;
		size_t packetBufferLength = 0;
		ssize_t err = 0;

		memset(packetBuffer, 0, sizeof(packetBuffer));
		cpa = (struct nd_certification_path_advert *) packetBuffer;

		send_ra_inc_len(&packetBufferLength, sizeof(struct nd_certification_path_advert));

		cpa->nd_cpa_type = ND_CERTIFICATION_PATH_ADVERT;
		cpa->nd_cpa_code = 0;
		cpa->nd_cpa_cksum = 0;
		/* identifier is taken from cps, no need to transform byte order */
		cpa->nd_cpa_identifier = identifier;
		/* The RFC 3971 isn't clear at this point.
		 * On the one hand it says, the all components field should contain the number of certificates in the path,
		 * but it does not clarify, if the trust anchor is considered as such.
		 * Since the trust anchor indeed is a certificate, we consider it to be part of the path.
		 * On the other hand, the name of the field suggests, that this is the number of CPAs one will receive,
		 * when requesting the whole path, which would be one less than the number of certificates in the path.
		 * We decided to trust the description instead of the field name here and
		 * fill it with the total number of certificates in the path. */
		cpa->nd_cpa_all_components = htons(stackSize);
		if (component != ND_CPS_COMPONENT_ALL) {
			cpa->nd_cpa_component = htons(component);
		} else {
			/* the last component has the component field set to 0 */
			cpa->nd_cpa_component = htons(cpaCount - 1);
		}
		cpa->nd_cpa_reserved = 0;

		/* add trust anchor option if this is the first CPA of a sequence of CPAs */
		if (component != ND_CPS_COMPONENT_ALL || (cpaCount == stackSize - 1)) {
			struct nd_opt_trust_anchor trustAnchor;
			fixedDataLen =	sizeof(trustAnchor.nd_opt_ta_type) +
							sizeof(trustAnchor.nd_opt_ta_len) +
							sizeof(trustAnchor.nd_opt_ta_name_type) +
							sizeof(trustAnchor.nd_opt_ta_pad_length);
			trustAnchor.nd_opt_ta_type = ND_OPT_TRUST_ANCHOR;
			if ((fixedDataLen + certPathToSend->trustAnchorNameLen) % 8 == 0) {
				trustAnchor.nd_opt_ta_len =	(fixedDataLen + certPathToSend->trustAnchorNameLen) / 8;
			} else {
				trustAnchor.nd_opt_ta_len = (fixedDataLen + certPathToSend->trustAnchorNameLen + (8 - ((fixedDataLen + certPathToSend->trustAnchorNameLen) % 8))) / 8;
			}
			trustAnchor.nd_opt_ta_name_type = certPathToSend->nameType;
			trustAnchor.nd_opt_ta_pad_length = (trustAnchor.nd_opt_ta_len * 8) - (fixedDataLen + certPathToSend->trustAnchorNameLen);
			trustAnchor.nd_opt_ta_name = certPathToSend->trustAnchorName;

			dlog(LOG_DEBUG, 5, "appending trust anchor option to first CPA of the path");

			packetBufferDestination = packetBufferLength;
			send_ra_inc_len(&packetBufferLength, trustAnchor.nd_opt_ta_len * 8);
			memcpy(packetBuffer + packetBufferDestination, &trustAnchor, fixedDataLen);
			packetBufferDestination += fixedDataLen;
			memcpy(packetBuffer + packetBufferDestination, trustAnchor.nd_opt_ta_name, certPathToSend->trustAnchorNameLen);
			packetBufferDestination += certPathToSend->trustAnchorNameLen;
			memset(packetBuffer + packetBufferDestination, 0, trustAnchor.nd_opt_ta_pad_length);
		}

		/* add certificate option */
		fixedDataLen =	sizeof(certificate.nd_opt_cert_type) +
						sizeof(certificate.nd_opt_cert_len) +
						sizeof(certificate.nd_opt_cert_cert_type) +
						sizeof(certificate.nd_opt_cert_reserved);

		/* find the needed certificate in the stack */
		if (component == ND_CPS_COMPONENT_ALL) {
			certData = sk_X509_delete(certPathToSend->certificateStack, stackSize - cpaCount);
			sk_X509_insert(certPathToSend->certificateStack, certData, stackSize - cpaCount);
		} else {
			certData = sk_X509_delete(certPathToSend->certificateStack, component);
			sk_X509_insert(certPathToSend->certificateStack, certData, component);
		}
		/* convert certificate to DER */
		certLen = i2d_X509(certData, NULL);
		p = malloc(certLen);
		if (p == NULL) {
			flog(LOG_ERR, "error while allocating buffer for DER encoded certificate");
			continue;
		}
		certificate.nd_opt_cert_certificate = p;
		i2d_X509(certData, &p);

		/* build certificate option */
		certificate.nd_opt_cert_type = ND_OPT_CERTIFICATE;
		if ((fixedDataLen + certLen) % 8 == 0) {
			certificate.nd_opt_cert_len = (fixedDataLen + certLen) / 8;
		} else {
			certificate.nd_opt_cert_len = (fixedDataLen + certLen + (8 - ((fixedDataLen + certLen) % 8))) / 8;
		}
		certificate.nd_opt_cert_cert_type = 1;
		certificate.nd_opt_cert_reserved = 0;

		/* append certificate option to cpa packet */
		packetBufferDestination = packetBufferLength;
		send_ra_inc_len(&packetBufferLength, certificate.nd_opt_cert_len * 8);
		memcpy(packetBuffer + packetBufferDestination, &certificate, fixedDataLen);
		packetBufferDestination += fixedDataLen;
		memcpy(packetBuffer + packetBufferDestination, certificate.nd_opt_cert_certificate, certLen);
		packetBufferDestination += certLen;
		memset(packetBuffer + packetBufferDestination, 0, certificate.nd_opt_cert_len - fixedDataLen);

		/* send the packet */
		memset((void *)&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(IPPROTO_ICMPV6);
		memcpy(&addr.sin6_addr, dest, sizeof(struct in6_addr));

		iov.iov_len  = packetBufferLength;
		iov.iov_base = (caddr_t) packetBuffer;

		memset(chdr, 0, sizeof(chdr));
		cmsg = (struct cmsghdr *) chdr;

		cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type  = IPV6_PKTINFO;

		pkt_info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		pkt_info->ipi6_ifindex = iface->if_index;
		memcpy(&pkt_info->ipi6_addr, &iface->if_addr, sizeof(struct in6_addr));

#ifdef HAVE_SIN6_SCOPE_ID
		if (IN6_IS_ADDR_LINKLOCAL(&addr.sin6_addr) ||
			IN6_IS_ADDR_MC_LINKLOCAL(&addr.sin6_addr))
				addr.sin6_scope_id = iface->if_index;
#endif

		memset(&mhdr, 0, sizeof(mhdr));
		mhdr.msg_name = (caddr_t)&addr;
		mhdr.msg_namelen = sizeof(struct sockaddr_in6);
		mhdr.msg_iov = &iov;
		mhdr.msg_iovlen = 1;
		mhdr.msg_control = (void *) cmsg;
		mhdr.msg_controllen = sizeof(chdr);

		err = sendmsg(sock, &mhdr, 0);

		if (err < 0) {
			if (!iface->IgnoreIfMissing || !(errno == EINVAL || errno == ENODEV))
				flog(LOG_WARNING, "sendmsg: %s", strerror(errno));
			else
				dlog(LOG_DEBUG, 3, "sendmsg: %s", strerror(errno));
		} else {
			++successCount;
		}

		/* free allocated memory */
		free(certificate.nd_opt_cert_certificate);
	}

	return successCount;
}

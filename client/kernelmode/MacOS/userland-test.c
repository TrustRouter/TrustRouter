#include <stdio.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sys_domain.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>

void ipv6_to_str_unexpanded(char * str, const struct in6_addr * addr) {
   sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 (int)addr->s6_addr[0], (int)addr->s6_addr[1],
                 (int)addr->s6_addr[2], (int)addr->s6_addr[3],
                 (int)addr->s6_addr[4], (int)addr->s6_addr[5],
                 (int)addr->s6_addr[6], (int)addr->s6_addr[7],
                 (int)addr->s6_addr[8], (int)addr->s6_addr[9],
                 (int)addr->s6_addr[10], (int)addr->s6_addr[11],
                 (int)addr->s6_addr[12], (int)addr->s6_addr[13],
                 (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}

struct result {
    void *packet_id;
    int32_t action;
};

int main() {
	int fd = socket(PF_SYSTEM, SOCK_STREAM, SYSPROTO_CONTROL);
    if (fd == -1) {
    	exit(-1);
    }
    struct sockaddr_ctl addr;
    bzero(&addr, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    struct ctl_info info;
    bzero(&info, sizeof(info));
    strncpy(info.ctl_name, "de.m-goderbauer.kext.trustrouter", sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info)) {
        printf("Could not get ID for kernel control.\n");
        exit(-1);
    }
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		printf("connect failed\n");
        exit(-1);
	}

    void *id;
    read(fd, &id, sizeof(id));

	struct ip6_hdr ip_hdr;
	read(fd, &ip_hdr, sizeof(ip_hdr));

    printf("New Router Advertisment (%p):\n", id);

    char* string_addr = malloc(24 * sizeof(char));
    ipv6_to_str_unexpanded(string_addr, &(ip_hdr.ip6_src));
    printf("    From:   %s\n", string_addr);

    ipv6_to_str_unexpanded(string_addr, &(ip_hdr.ip6_dst));
    printf("    To:     %s\n", string_addr);

    struct nd_router_advert ra;
	read(fd, &ra, sizeof(ra));

	struct nd_opt_prefix_info prefix;
	read(fd, &prefix, sizeof(prefix));
	ipv6_to_str_unexpanded(string_addr, &(prefix.nd_opt_pi_prefix));
	printf("    Prefix: %s/%d\n", string_addr, prefix.nd_opt_pi_prefix_len);

    char a;
    printf("Do you trust this RA? (y/n): ");
    scanf ("%c", &a);
    struct result result;
    result.packet_id = id;

    if (a == 'y') {
        result.action = 0;
        printf("Accepted\n");
    } else {
        result.action = -1;
        printf("Rejected\n");
    }
    send(fd, &result, sizeof(result), 0);

	free(string_addr);
	close(fd);
}


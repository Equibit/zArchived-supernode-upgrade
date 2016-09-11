#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>


bool get_mac( unsigned char * mac_address )
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (sock == -1) 
		return false;

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;

    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) 
		return false;

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) 
	{
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) 
		{
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) 
			{ 
				// don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) 
				{
                    success = 1;
                    break;
                }
            }
        }
    }

    if (success) 
	{
		memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
		return true;
	}
	else
		return false;
}

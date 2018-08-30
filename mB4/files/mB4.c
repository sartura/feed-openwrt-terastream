/*
  * Software Name: mB4 according to draft-qin-softwire-dslite-multicast-02
  * Version: 01


  *Copyright: 12/18/2011 France Telecom
  *This software is distributed under the Apache 2.0 license,
  *the text of which is available at http://www.apache.org/licenses/LICENSE-2.0.html



  *
  *-----------------------------------------------------
  * File Name : mB4-v1.0.c
  *
  * Created   : 12/2011
  * Author(s) : Xiaohong Deng, Zhenyu Lei, Xu Wang, Jiang Li
  *
  * Description :

  * checksum : calculate the checksum of packets
  * checksum1 : 
  * csum : 
  * compare : compare which bigger between a and b
  * readconfig : read config data from a specific file
  * get_if_index : return the interface index based on the interface name
  * set_if_multicast : set a socket to support  multicast
  * set_if_promisc : set a device to be promisc mode
  * print_packet_content : print the content of a packet in the buffer
  * translation_mode : translate the udp packet from ipv6 mode to ipv4 mode
  * encapslation_mode : translate the udp packet from v4 over v6 mode to ipv4 mode
  * igmpv2_rep_2_mld : translate the igmpv2 packet to mldv1 
  * handle_icmpv6 : translate mld query message to igmpv2 packet
  * ----------------------------------------------------
  */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//isspace()
#include <ctype.h>

/*socket() setsockopt()*/
#include <sys/types.h>
#include <sys/socket.h>

/* inet_ntoa() */
#include <netinet/in.h>
#include <arpa/inet.h>

/* select */
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

/* struct iphdr */
#include <netinet/ip.h>

/*struct ip6_hdr */
#include <netinet/ip6.h>


/* struct udphdr */
#include <linux/udp.h>
/* struct igmp */
#include <netinet/igmp.h>


/* ioctl */
#include <sys/ioctl.h>

/* struct sockaddr_ll && struct packet_mreq */
#include <netpacket/packet.h>

/* ETH_P_ALL */
#include <linux/if_ether.h>

/*struct ifreq*/
#include <net/if.h>

#include <linux/igmp.h>

//#include <net/if_arp.h>

#define MLD_QUERY 0x82 //130
#define MLD_REPORT 0x83 //131
#define MLD2_REPORT 0x8F //143
#define MLD_DONE 0x84 //132

#define SRC_PREFIX "2003:1b0b:fffd:ffff::"
#define V6_PREFIX "ff38:0:0:0:e90a::"
#define MLDV2_SOURCE "2003:1b0b:fffd:ffff:0:c613:8c01:0"

#define MLD_QUERY_ADDR "ff02::1"
#define MLD_LEAVE_ADDR "ff02::2"

#define IGMP_MULTICASTADDR "224.0.0.1"



#define RED		"\E[31m\E[1m"
#define GREEN	"\E[32m\E[1m"
#define YELLOW	"\E[33m\E[1m"
#define BLUE	"\E[34m\E[1m"
#define NORMAL	"\E[m"

#define DEBUG_INFO


int m_send_trs_fd, m_send_encp_fd;


struct ip6_hdr *ip6_h;


int trans_mode = 0;//mode 1 for translation mode

char in_port[10];
char out_port[10];
char config_file[] = "/etc/multi_forward.conf";


unsigned short checksum(int len, unsigned char *buffer)
{
        unsigned long cksum = 0;
        unsigned short *p=(unsigned short*)buffer;
        int size=(len>>1)+(len&0x1);
        while (size > 0) {
                cksum += *p;
                p++;
                size--;
        }
        cksum = (cksum >> 16) + (cksum & 0xffff);
        cksum += (cksum >> 16);
        return (unsigned short) (~cksum);
}


unsigned short checksum1(unsigned short *buf,int nword)//nword number of 16bit
{
	unsigned long sum;
	for(sum=0;nword>0;nword--)//add at each 16bit
		sum += *buf++;

	while (sum >> 16)//high bits add to low bits
		sum = (sum & 0xffff) + (sum >> 16);
return (unsigned short)(~sum);
}


unsigned short csum(unsigned short *buffer, int size){
	unsigned long cksum = 0;
	while(size > 1){
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if(size){
		cksum += *(unsigned char *)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}




int compare(int a, int b){
	return a >= b ? a : b;
}


int readconfig(const char *file){
	FILE *f = NULL;
	char line_buf[256];
	int line_num =0;
	char *back_space;
	char *name;
	char *equal;
	char *value;
	int value_len = 0;
	char mode_flag[4];

	printf("mikabr binary.\n");

	memset(line_buf, 0, sizeof(line_buf));

	memset(in_port, 0, sizeof(in_port));
	memset(out_port, 0, sizeof(out_port));
	memset(mode_flag, 0, sizeof(mode_flag));
	
	if((f = fopen(file, "r")) == NULL){
		printf("fopen file error\n");
		return -1;
	}

	fseek(f, 0, SEEK_SET);
	while(fgets(line_buf, sizeof(line_buf), f) !=NULL){
		line_num++;
		back_space = strchr(line_buf, '\n');

		
		if(back_space){//delete the space from the end of line
			*back_space= '\0';
			back_space--;
			while((back_space >= line_buf) && isspace(*back_space)){
				*back_space= '\0';
				back_space--;
			}
			
		}

		//delete the space from header of the line
		name = line_buf;
		while(isspace(*name))
			name++;

		//#line for comments and empty lines ignore
		if(name[0] == '#' || name[0] == '\0')
			continue;

		if(memcmp(name, "ChangeModeToTranslation", 13) == 0){
			if(!(equal = strchr(name, '='))){
				printf("ChangeModeToTranslation empty will be in encapslation mode\n");
				continue;
			}
			value = equal + 1;

			//skip leading whitespaces
			while(isspace(*value))
				value++;

			value_len = strlen(value);
			
			memcpy(mode_flag, value, value_len);
			if((memcmp(mode_flag, "yes", 3) == 0)||(memcmp(mode_flag, "Yes", 3) == 0)||(memcmp(mode_flag, "YES", 3) == 0)){
				trans_mode = 1;
			}
		}
		else if(memcmp(name, "In_port", 7) == 0){
			if(!(equal = strchr(name, '='))){
				printf("In_port empty need to be configured\n");
				continue;
			}
			value = equal + 1;

			//skip leading whitespaces
			while(isspace(*value))
				value++;

			value_len = strlen(value);
			
			memcpy(in_port, value, value_len);
		}
		else if(memcmp(name, "Out_port", 8) == 0){
			if(!(equal = strchr(name, '='))){
				printf("Out_port empty need to be configured\n");
				continue;
			}
			value = equal + 1;

			//skip leading whitespaces
			while(isspace(*value))
				value++;

			value_len = strlen(value);
			
			memcpy(out_port, value, value_len);

		}
		else{
			continue;
		}
		if(fgetc(f)==EOF){
			break;  
		}
		fseek(f,-1,SEEK_CUR); 
		
		memset(line_buf, 0, sizeof(line_buf));
		
	}

	#ifdef DEBUG_INFO
	printf("mode_flag :%s\n", mode_flag);
	printf("in_port:%s\n", in_port);
	printf("out_port:%s\n", out_port);

	#endif
	fclose(f);
	return 1;
}


int get_if_index(int fd, const char *if_name){
	struct ifreq ifr;
	if(if_name == NULL){
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, if_name);
	if(ioctl(fd, SIOCGIFINDEX, &ifr) == -1){
		printf("RED ioctl error\n");
		return -1;
	}
	return ifr.ifr_ifindex;
	
}

int set_if_multicast(int fd, int dev_id){
	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = dev_id;
	//mr.mr_type = PACKET_MR_PROMISC;
	mr.mr_type = PACKET_MR_MULTICAST;
	//mr.mr_type = PACKET_MR_ALLMULTI;

	if(setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1){
		fprintf(stderr, "GREEN set promisc failed!\n");
		return -1;
	}
	
	return 0;
}


int set_if_promisc(int fd, int dev_id){
	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = dev_id;
	mr.mr_type = PACKET_MR_PROMISC;
	//mr.mr_type = PACKET_MR_MULTICAST;
	//mr.mr_type = PACKET_MR_ALLMULTI;

	if(setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1){
		fprintf(stderr, "GREEN set promisc failed!\n");
		return -1;
	}
	
	return 0;
}



/*
void usage(char *program){
	fprintf(stderr, RED"%s <num of packets to capture>\n"NORMAL, program);
}
*/

int print_packet_content(unsigned char *pBuf, int bufLen)
{
    int count = 0;    
	printf("\n**********\n");

    printf("packet content:\n");
    
    if ((NULL == pBuf) || (0 == bufLen))
    {
        printf("null packet\n");
        return -1;
    }

    for (count = 0; count < bufLen; count++)
    {
        printf("%2x ", pBuf[count]);
        if ((count+1) % 8 == 0 )
        {
            printf("\n");
        }
    }
	printf("\n");

    return 0;
}

int translation_mode(char *m_buffer, int frm_len){
	struct udphdr *udp_h;

	struct sockaddr_in send_addr;

		/* tmp var*/
	char c_src_6[INET6_ADDRSTRLEN], c_dst_6[INET6_ADDRSTRLEN];
	char *p;
	char *to_send;
	
	struct in6_addr tmp_v6;
	struct in_addr get_multi_v4;

	int data_len = 0;
	
	memset(c_dst_6, 0, sizeof(c_dst_6));
	memset(c_src_6, 0, sizeof(c_src_6));
	memset(&get_multi_v4, 0, sizeof(struct in_addr));
	memset(&tmp_v6, 0, sizeof(struct in6_addr));

	memset(&send_addr, 0, sizeof(struct sockaddr_in)); 

	send_addr.sin_family = AF_INET;
		
	ip6_h = (struct ip6_hdr*)(m_buffer + sizeof(struct ethhdr));

	if (inet_ntop(AF_INET6, &(ip6_h->ip6_src), c_src_6, sizeof(c_src_6)) <= 0) {
		perror("inet_ntop:");
		printf("translation_mode: inet_ntop: error from\n");
		return -1;
	}

	printf("IPv6 Packet from: %s\n", c_src_6);

	if (inet_ntop(AF_INET6, &(ip6_h->ip6_dst), c_dst_6, sizeof(c_dst_6)) <= 0) {
				perror("inet_ntop:");
				printf("translation_mode: inet_ntop: error to\n");
				return -1;
	}

	printf("IPv6 Packet to: %s\n", c_dst_6);


	/*get ipv4 addr from ipv6 addr*/
	tmp_v6 = ip6_h->ip6_dst;
	p = (char *)tmp_v6.s6_addr;
	printf("1\n");
	memcpy(&get_multi_v4, (p+12), 4);
	printf("2\n");
	/*
	find_multi_v4 = p +12;
	printf("2\n");
	printf("last4 %s\n", find_multi_v4);
	memcpy(&get_multi_v4, find_multi_v4, 4);
	printf("3\n");
	*/

	#ifdef DEBUG_INFO
	printf(RED"--IPv6 to IPv4 get group address: %s\n"NORMAL,inet_ntoa(get_multi_v4));
	#endif

	//set send ipv4 addr
	memcpy(&send_addr.sin_addr, &get_multi_v4, sizeof(get_multi_v4));



			/*TODO : nextheader handle */

	//printf(RED"NEXT HEADER : %d(UDP:17 TCP:6)\n"NORMAL,ip6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt);

	if(ip6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt != 17){
		printf(RED"NEXT HEADER NOT UDP, drop Packet!!\n"NORMAL);
		return -1;
	}


	udp_h = (struct udphdr*)(m_buffer + sizeof(struct ethhdr) +sizeof(struct ip6_hdr));

	#ifdef DEBUG_INFO
	printf("Source port : %d\n",ntohs(udp_h->source));
	printf("Destination port : %d\n",ntohs(udp_h->dest));
	#endif

	//set send dest port
	send_addr.sin_port = udp_h->dest;
	#ifdef DEBUG_INFO
	printf("Destination port to send!!: %d\n",ntohs(send_addr.sin_port));
	#endif

	data_len = frm_len - (sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr));
	to_send = m_buffer + sizeof(struct ethhdr) +sizeof(struct ip6_hdr) + sizeof(struct udphdr);

			
	if(sendto(m_send_trs_fd, (void *)to_send, data_len, 0, (struct sockaddr *)&send_addr, sizeof(struct sockaddr_in)) < 0){//send to group
		printf(stderr, RED"send error!\n"NORMAL);
		perror("send_to");
		return -1;
	}
	else{
		printf(GREEN"Forward send success!\n"NORMAL);
		return 1;
	}


	return 0;
}

int encapslation_mode(char *m_buffer, int frm_len){
	//struct ip6_hdr *ip6_h;
	struct iphdr *ip_h;


	struct sockaddr_ll sll_out;

	char * to_send;

		/* tmp var*/
	#ifdef DEBUG_INFO
	char c_src_6[INET6_ADDRSTRLEN], c_dst_6[INET6_ADDRSTRLEN];
	#endif
	int send_len =0, data_len =0;
	unsigned int tmp_dst =0;

	
	memset(&sll_out, 0, sizeof(sll_out));
	#ifdef DEBUG_INFO
	memset(c_dst_6, 0, sizeof(c_dst_6));
	memset(c_src_6, 0, sizeof(c_src_6));
	#endif


	/*mac address set*/
	sll_out.sll_family = AF_PACKET;
	
	if((sll_out.sll_ifindex = get_if_index(m_send_encp_fd, out_port)) == -1){
		printf("encap eth0 if_index error\n");
	}
	sll_out.sll_protocol = htons(ETH_P_IP);
	sll_out.sll_pkttype = PACKET_OUTGOING;
	sll_out.sll_halen = 6;

	memset(sll_out.sll_addr, 0, sizeof(sll_out.sll_addr));
	sll_out.sll_addr[0]= 0X01;
	sll_out.sll_addr[1]= 0X00;
	sll_out.sll_addr[2]= 0X5e;
	//0X01005E FOR multicast MAC address 	


	ip6_h = (struct ip6_hdr*)(m_buffer + sizeof(struct ethhdr));

	#ifdef DEBUG_INFO
	/* For debug*/
	if (inet_ntop(AF_INET6, &(ip6_h->ip6_src), c_src_6, sizeof(c_src_6)) <= 0) {
		perror("inet_ntop:");
		printf("encapsulation_mode: error ntop from\n");
		return -1;
	}

	printf("encapsulation_mode: IPv6 Packet from: %s\n", c_src_6);

	if (inet_ntop(AF_INET6, &(ip6_h->ip6_dst), c_dst_6, sizeof(c_dst_6)) <= 0) {
				perror("inet_ntop:");
				printf("encapsulation_mode: error ntop to:\n");
				return -1;
	}

	printf("encapsulation_mode: IPv6 Packet to: %s\n", c_dst_6);
	#endif


	ip_h = (struct iphdr*)(m_buffer + sizeof(struct ethhdr)+sizeof(struct ip6_hdr));	//sizeof(struct ip6_hdr) ipv6 header length need to 

	/*put lower 23bits of dst_ip into MAC dst addr*/
	tmp_dst = ntohl(ip_h->daddr);

	tmp_dst = tmp_dst << 9;
	tmp_dst = tmp_dst >> 9;
	/*
	tmp_dst = htonl(tmp_dst);
	printf("--tmp dst: %s\n",inet_ntoa(*(struct in_addr*)&(tmp_dst)));
	
	tmp_dst = ntohl(tmp_dst);
	*/


	tmp_dst = tmp_dst << 8;
	tmp_dst = htonl(tmp_dst);
	printf("--tmp dst: %s\n",inet_ntoa(*(struct in_addr*)&(tmp_dst)));
	memcpy(sll_out.sll_addr+3, &tmp_dst, 3);

	data_len = frm_len - (sizeof(struct ethhdr) + sizeof(struct ip6_hdr));//sizeof(struct ip6_hdr) ipv6 header length need to 
	printf("data_len = %d\n",data_len);
	to_send = m_buffer + sizeof(struct ethhdr) +sizeof(struct ip6_hdr);//sizeof(struct ip6_hdr) ipv6 header length need to 

	if((send_len = sendto(m_send_encp_fd, to_send, data_len, 0, (struct sockaddr *)&sll_out, sizeof(sll_out))) < 0){
		printf(RED"send error: %d"NORMAL, send_len);
		perror("send");
		//print_packet_content(to_send, data_len);
		return -1;
	}
	else{
		#ifdef DEBUG_INFO
		printf(GREEN"Encapsulation Forward send success!\n"NORMAL);
		//print_packet_content(to_send, data_len);
		#endif
		return 1;
	}
	return 0;
}


int igmpv2_rep_2_mld(struct igmp* buf, char *src){
	struct igmp *igmp;
	igmp =(struct igmp *)buf;
	//int i;

	int mld_sock;
	unsigned short chk;
	

	struct ip6_hdr ip6_hdr;
	struct ip6_hbh ip6_hbh;
	unsigned char router_alert[4], padding[2];
	


	char send[72];//mld24 + hbh8 +ipv640
	char send2[92];//mld44 + hbh8 +ipv640
	char mld_msg[24];
	char mld_msg2[44];
	unsigned char buf_for_chk[64];//mld24 predo header 40
	unsigned char buf_for_chk2[84];//mld44 predo header 40

	char multi_addr6[INET6_ADDRSTRLEN];
	char multi_addr6_src[INET6_ADDRSTRLEN];
	char multi_addr[INET_ADDRSTRLEN];
	char c_src_addr6[INET6_ADDRSTRLEN];

	memset(&ip6_hdr, 0, sizeof(ip6_hdr));
	memset(&ip6_hbh, 0, sizeof(ip6_hbh));
	memset(router_alert, 0, sizeof(router_alert));
	memset(padding, 0, sizeof(padding));

	memset(send, 0, sizeof(send));
	memset(mld_msg, 0, sizeof(mld_msg));
	memset(mld_msg2, 0, sizeof(mld_msg2));
	memset(buf_for_chk, 0, sizeof(buf_for_chk));
	memset(buf_for_chk2, 0, sizeof(buf_for_chk2));
	memset(multi_addr, 0, sizeof(multi_addr));
	memset(multi_addr6, 0, sizeof(multi_addr6));
	memset(multi_addr6_src, 0, sizeof(multi_addr6_src));
	memset(c_src_addr6, 0, sizeof(c_src_addr6));


	router_alert[0]=0x05;
	router_alert[1]=0x02;

	padding[0]=0x01;

	struct sockaddr_in6 mld_dst6, src6;


	memset(&mld_dst6, 0, sizeof(mld_dst6));
	mld_dst6.sin6_family = AF_INET6;

	memset(&src6, 0, sizeof(src6));
	src6.sin6_family = AF_INET6;
	/*
	if( (mld_sock=socket(AF_INET6,SOCK_RAW,IPPROTO_ICMPV6) )<0)
	{
		perror("socket error");
		exit(1);
	}
	*/

	if((mld_sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6)))<0){
		perror("socket");
		return -1;
	}

	#ifdef DEBUG
	printf(YELLOW"\n===========================\n"NORMAL);
	printf("IGMP type : %d\n",igmp->igmp_type);
	printf("--IGMP group: %s\n",inet_ntoa(igmp->igmp_group));
	#endif

	sprintf(multi_addr, "%s", inet_ntoa(igmp->igmp_group));

	#ifdef DEBUG
	printf("multi_addr: %s\n",multi_addr);
	#endif
	memcpy(multi_addr6, V6_PREFIX, strlen(V6_PREFIX));
	memcpy(multi_addr6+ strlen(V6_PREFIX),  multi_addr, strlen(multi_addr));


	struct sockaddr_ll igmp_out;
	memset(&igmp_out, 0, sizeof(igmp_out));

	igmp_out.sll_family = AF_PACKET;
	
	if((igmp_out.sll_ifindex = get_if_index(mld_sock, in_port)) == -1){
		printf("encap eth0 if_index error\n");
	}
	igmp_out.sll_protocol = htons(ETH_P_IPV6);
	igmp_out.sll_pkttype = PACKET_OUTGOING;
	igmp_out.sll_halen = 6;

	memset(igmp_out.sll_addr, 0, sizeof(igmp_out.sll_addr));
	igmp_out.sll_addr[0]= 0X33;
	igmp_out.sll_addr[1]= 0X33;


	
	//memcpy(&ip6_hdr.ip6_un1.ip6_un1_flow, "",4);	
	ip6_hdr.ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
	ip6_hdr.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(0x0020);
	ip6_hdr.ip6_ctlun.ip6_un1.ip6_un1_nxt = 0x00;
	ip6_hdr.ip6_ctlun.ip6_un1.ip6_un1_hlim = 0x01;
		
	if (inet_pton(AF_INET6, "fe80::38ec:6dff:fe29:dde9", &ip6_hdr.ip6_src) <= 0) {
	//if (inet_pton(AF_INET6, "2001:ffff:ffff:400::1", &ip6_hdr.ip6_src) <= 0) {
		perror("inet_pton 1");
		return -1;
	}


	ip6_hbh.ip6h_nxt = 0x3a;
	

	/*in pseudo header payload len = MLD packet len ##checksum  soucrce address how to get##*/
	switch(igmp->igmp_type){
		case IGMP_MEMBERSHIP_QUERY/*0X11*/:
			printf(RED"IGMP QUERY MSG should not appear!!\n"NORMAL);
			break;
			
		case IGMP_V1_MEMBERSHIP_REPORT/*0X12 dst = specific V6 group address */:
			printf(GREEN"IGMPv1 report MSG !!\n"NORMAL);
			break;
		case IGMP_V2_MEMBERSHIP_REPORT/*0X16 dst = specific V6 group address*/:
			printf(GREEN"IGMP_V2_MEMBERSHIP_REPORT: IGMPv2 report MSG !!\n"NORMAL);

			mld_msg[0] = MLD_REPORT;//type
			mld_msg2[0] = MLD2_REPORT;//type
			//mld_msg+2 checksum

			//memcpy(c_src_addr6, SRC_PREFIX, strlen(SRC_PREFIX));
			//memcpy(c_src_addr6+ strlen(SRC_PREFIX),  src, strlen(src));

			memcpy(multi_addr6, V6_PREFIX, strlen(V6_PREFIX));
			memcpy(multi_addr6+ strlen(V6_PREFIX),  multi_addr, strlen(multi_addr));

			printf("IGMP_V2_MEMBERSHIP_REPORT: multi_addr ipv6: %s\n", multi_addr6);
			printf("IGMP_V2_MEMBERSHIP_REPORT: MLDv2 source ipv6: %s\n", MLDV2_SOURCE);
			memcpy(multi_addr6_src, MLDV2_SOURCE, strlen(MLDV2_SOURCE));
		
			printf("IGMP_V2_MEMBERSHIP_REPORT: multi_addr6_src ipv6: %s\n", multi_addr6_src);


			if (inet_pton(AF_INET6, multi_addr6, mld_msg + 8) <= 0) {
				perror("inet_pton multi_addr6 ");
				printf("IGMP_V2_MEMBERSHIP_REPORT ERROR exit");
				return -1;
			}

			mld_msg2[7] = 1; // set number of address record
			mld_msg2[8] = 1; // set mld address record type
			mld_msg2[11] = 1; // set number of sources
			if (inet_pton(AF_INET6, multi_addr6, mld_msg2 + 12) <= 0) {
				perror("inet_pton multi_addr6 ");
				printf("IGMP_V2_MEMBERSHIP_REPORT ERROR exit");
				return -1;
			}
			printf("IGMP_V2_MEMBERSHIP_REPORT: MLDv2 source ipv6: %s\n", multi_addr6_src);
			if (inet_pton(AF_INET6, multi_addr6_src, mld_msg2 + 28) <= 0) {
				perror("inet_pton MLDv2 source ");
				printf("IGMP_V2_MEMBERSHIP_REPORT ERROR exit MLDv2 source %s test\n",multi_addr6_src);
				return -1;
			}

			if (inet_pton(AF_INET6, multi_addr6, &ip6_hdr.ip6_dst) <= 0) {
				perror("inet_pton 1 ");
				printf("IGMP_V2_MEMBERSHIP_REPORT ERROR exit");
				return -1;
			}


			memcpy(buf_for_chk, mld_msg, sizeof(mld_msg));
			memcpy(buf_for_chk+sizeof(mld_msg), &ip6_hdr.ip6_src, 16);
			memcpy(buf_for_chk+sizeof(mld_msg)+16, &ip6_hdr.ip6_dst, 16);
			*(buf_for_chk+sizeof(mld_msg)+35) = 0x18;//upper layer packet 
			*(buf_for_chk+sizeof(mld_msg)+39) = 0x3a;
			chk = checksum(sizeof(buf_for_chk), buf_for_chk);
			memcpy(mld_msg+2, &chk, sizeof(chk));

			memcpy(buf_for_chk2, mld_msg2, sizeof(mld_msg2));
			memcpy(buf_for_chk2+sizeof(mld_msg2), &ip6_hdr.ip6_src, 16);
			memcpy(buf_for_chk2+sizeof(mld_msg2)+16, &ip6_hdr.ip6_dst, 16);
			*(buf_for_chk2+sizeof(mld_msg2)+35) = 0x18;//upper layer packet 
			*(buf_for_chk2+sizeof(mld_msg2)+39) = 0x3a;
			chk = checksum(sizeof(buf_for_chk2), buf_for_chk2);
			memcpy(mld_msg2+2, &chk, sizeof(chk));
	
			memcpy(send, &ip6_hdr, sizeof(ip6_hdr));
			memcpy(send+sizeof(ip6_hdr), &ip6_hbh, 2);
			memcpy(send+sizeof(ip6_hdr)+2, router_alert, 4);
			memcpy(send+sizeof(ip6_hdr)+6, padding, 2);
			memcpy(send+sizeof(ip6_hdr)+8, mld_msg, sizeof(mld_msg));

			memcpy(send2, &ip6_hdr, sizeof(ip6_hdr));
			memcpy(send2+sizeof(ip6_hdr), &ip6_hbh, 2);
			memcpy(send2+sizeof(ip6_hdr)+2, router_alert, 4);
			memcpy(send2+sizeof(ip6_hdr)+6, padding, 2);
			memcpy(send2+sizeof(ip6_hdr)+8, mld_msg2, sizeof(mld_msg2));


			memcpy(igmp_out.sll_addr+2, &igmp->igmp_group, sizeof(igmp->igmp_group));
/*			if(sendto(mld_sock, send, sizeof(send), 0, (struct sockaddr *)&igmp_out, sizeof(igmp_out)) < 0){
				perror("sendto");
				printf(RED"IGMP_V2_MEMBERSHIP_REPORT: IGMPv2 report MSG to MLD failed !!\n"NORMAL);
				return -1;
			}
			else{
				printf(GREEN"IGMP_V2_MEMBERSHIP_REPORT: IGMPv2 report MSG to MLD success  !!\n"NORMAL);
			}*/

			print_packet_content(send2, sizeof(send2));
			if(sendto(mld_sock, send2, sizeof(send2), 0, (struct sockaddr *)&igmp_out, sizeof(igmp_out)) < 0){
				perror("sendto");
				printf(RED"IGMP_V2_MEMBERSHIP_REPORT: IGMPv2 report MSG to MLD2 failed !!\n"NORMAL);
				return -1;
			}
			else{
				printf(GREEN"IGMP_V2_MEMBERSHIP_REPORT: IGMPv2 report MSG to MLD2 success  !!\n"NORMAL);
			}





			break;
		case IGMP_V2_LEAVE_GROUP/*0X17 dst = FF02::2 */:
			printf(GREEN"IGMP LEAVE MSG !!\n"NORMAL);

			
			mld_msg[0] = MLD_DONE;//type
			//mld_msg+2 checksum


			memcpy(multi_addr6, V6_PREFIX, strlen(V6_PREFIX));
			memcpy(multi_addr6+ strlen(V6_PREFIX),  multi_addr, strlen(multi_addr));

			printf("IGMP_V2_LEAVE_GROUP : multi_addr ipv6: %s\n", multi_addr6);


			if (inet_pton(AF_INET6, multi_addr6, mld_msg + 8) <= 0) {
				perror("inet_pton multi_addr6");
				return -1;
			}
			if (inet_pton(AF_INET6, MLD_LEAVE_ADDR, &ip6_hdr.ip6_dst) <= 0) {
				perror("inet_pton 1");
				return -1;
			}


			memcpy(buf_for_chk, mld_msg, sizeof(mld_msg));
			memcpy(buf_for_chk+sizeof(mld_msg), &ip6_hdr.ip6_src, 16);
			memcpy(buf_for_chk+sizeof(mld_msg)+16, &ip6_hdr.ip6_dst, 16);
			*(buf_for_chk+sizeof(mld_msg)+35) = 0x18;//upper layer packet 
			*(buf_for_chk+sizeof(mld_msg)+39) = 0x3a;
			chk = checksum(sizeof(buf_for_chk), buf_for_chk);
			//chk = checksum1((unsigned short *)buf_for_chk, sizeof(buf_for_chk)/2);
			//chk = htons(chk);
			memcpy(mld_msg+2, &chk, sizeof(chk));
			
			memcpy(send, &ip6_hdr, sizeof(ip6_hdr));
			memcpy(send+sizeof(ip6_hdr), &ip6_hbh, 2);
			memcpy(send+sizeof(ip6_hdr)+2, router_alert, 4);
			memcpy(send+sizeof(ip6_hdr)+6, padding, 2);
			memcpy(send+sizeof(ip6_hdr)+8, mld_msg, sizeof(mld_msg));



			igmp_out.sll_addr[5]= 0X02;
			if(sendto(mld_sock, send, sizeof(send), 0, (struct sockaddr *)&igmp_out, sizeof(igmp_out)) < 0){
				perror("sendto");
				printf(RED"IGMP_V2_LEAVE_GROUP: IGMPv2 leave MSG to MLD failed  !!\n"NORMAL);
				return -1;
			}
			else{
				printf(GREEN"IGMPv2 leave MSG to MLD success  !!\n"NORMAL);
			}

			
			break;
		default :
			
			printf(RED"IGMP unrecognized MSG !!\n"NORMAL);
			break;

		
	}
	return 0;
}



//WX
int handle_icmpv6(int sockfd, struct sockaddr_in send_addr, char *buf){
	printf("handle icmpv6!\n");
	char *tmp;
	struct igmphdr igmp_hdr;
        unsigned short int max_res_delay;
	
	//14(Ethernet) + 6(IPv6 next header)
	tmp = buf + 14 + 6;
	//Hop-by-Hop Option
	if(*((unsigned char *)tmp) == 0x00){
		tmp += 34;
		printf("have hop by hop option!\n");
	}
	if(*((unsigned char *)tmp) == 0x3a){
		tmp += 8;
		printf("This is a icmpv6 packet!\n");
	}else{
		printf("packet may be broken...\n");
	}
	if(*((unsigned char *)tmp) != 0x82){
		printf("packet style is wrong!\n");
	}
	
	memset(&igmp_hdr, 0, sizeof(igmp_hdr));	
	igmp_hdr.type = 0x11;
	//from icmpv6 header to max response delay
	tmp += 4;
	memcpy(&max_res_delay, tmp, 2);
	max_res_delay = ntohs(max_res_delay);
	igmp_hdr.code = max_res_delay/100;
	printf("%d\n", max_res_delay);
	//frome max response delay to the end of multicast address prefix
	tmp += 2 + 12 +2;
	memcpy(&igmp_hdr.group, tmp, 4);
	igmp_hdr.csum = csum((unsigned short *)&igmp_hdr, sizeof(igmp_hdr));
	//igmp_hdr.csum = htons(igmp_hdr.csum);
	int sss = sendto(sockfd, &igmp_hdr, sizeof(igmp_hdr), 0, (struct sockaddr *)&send_addr, sizeof(send_addr));
	if(sss < 0)perror("sendto");
	return 0;
}


int main(int argc, char **argv){

	int multi_lis_data_fd6, multi_lis_igmp_fd4, m_send_fd6;

	char m_buffer[8192];


	struct sockaddr_ll sll, sll_out;//for set interface

	struct iphdr *ip_h;
	struct igmp *igmp_h;
	struct igmphdr *igmp_hdr;
	char src_addr[INET_ADDRSTRLEN];


	fd_set recv_fds;
	struct timeval timeout;
	int ret, r;

	int round = 0, i=0, frm_len =0;


	int m_igmp_fd;
	struct sockaddr_in igmp_addr;

	//struct sockaddr_in6 send_addr6;
	/*
	if(argc < 2){
		usage(argv[0]);
		return -1;
	}
	*/

	memset(src_addr, 0, sizeof(src_addr));

	if(readconfig(config_file) == -1){
		printf("readconfig error\n");
		exit(1);
	}

	if((m_send_trs_fd = socket(AF_INET, SOCK_DGRAM, 0))<0){
		perror("socket");
		return -1;
	}
	if((m_send_encp_fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP)))<0){
		perror("socket");
		return -1;
	}
	
	//m_listen_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	//m_listen_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	multi_lis_data_fd6 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));

	sll.sll_family = AF_PACKET;
	if((sll.sll_ifindex = get_if_index(multi_lis_data_fd6, in_port)) == -1){
		printf("v6 lo if_index error\n");
	}//add to config file
	sll.sll_protocol = htons(ETH_P_IPV6);
	//sll.sll_protocol = htons(ETH_P_ALL);
	//sll.sll_protocol = htons(ETH_P_IP);

	if(bind(multi_lis_data_fd6,(struct sockaddr *)(&sll), sizeof(sll)) == -1){
		fprintf(stderr, "bind error:%s!\n", strerror(errno));
		return -1;
	}

	//if(set_if_multicast(multi_lis_data_fd6, sll.sll_ifindex) == -1){
	if(set_if_promisc(multi_lis_data_fd6, sll.sll_ifindex) == -1){
		
		fprintf(stderr, "BLUEset promisc error!\n");
		return -1;
	}

	//set socket for listen ipv4 igmp msg
	multi_lis_igmp_fd4 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	sll.sll_family = AF_PACKET;
	if((sll.sll_ifindex = get_if_index(multi_lis_igmp_fd4, out_port))==-1){
		printf("main eth0 if_index error\n");
	}
	//sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_protocol = htons(ETH_P_IP);

	if(bind(multi_lis_igmp_fd4,(struct sockaddr *)(&sll), sizeof(sll)) == -1){
		fprintf(stderr, "bind error:%s!\n", strerror(errno));
		return -1;
	}

	if(set_if_promisc(multi_lis_igmp_fd4, sll.sll_ifindex) == -1){
		fprintf(stderr, "BLUEset promisc error!\n");
		return -1;
	}


	round = atoi(argv[1]);

	FD_ZERO(&recv_fds);

	//igmp socket WX
	m_igmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
	//setsockopt(m_igmp_fd, IPPROTO_IP, MRI_INIT, (void *)&enable_multi_forwarding, sizeof(enable_multi_forwarding));
	bzero(&igmp_addr, sizeof(igmp_addr));
	igmp_addr.sin_family = AF_INET;
	if(inet_aton(IGMP_MULTICASTADDR, &igmp_addr.sin_addr) < 0){
		printf("invalid IP address:%s\n", IGMP_MULTICASTADDR);
	}


	for(;;){
		#ifdef DEBUG_INFO
		printf(BLUE"\n\t%d select\n"NORMAL, i+1);
		printf(GREEN"\n\tFD_ISSET: %d\n"NORMAL, FD_ISSET(multi_lis_data_fd6, &recv_fds));
		#endif
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		FD_SET(multi_lis_data_fd6, &recv_fds);
		FD_SET(multi_lis_igmp_fd4, &recv_fds);

		ret = select(compare(multi_lis_igmp_fd4, multi_lis_data_fd6)+1, &recv_fds, NULL, NULL, &timeout);

		if(ret == -1){
			fprintf(stderr, "select error!\n");
			return -1;
		}

		#ifdef DEBUG_INFO
		printf(GREEN"\n\tSelect result: %d\n"NORMAL, ret);
		#endif

		
		if(FD_ISSET(multi_lis_data_fd6, &recv_fds)){
			memset(m_buffer, 0, sizeof(m_buffer));
			frm_len = recv(multi_lis_data_fd6, m_buffer, 8192, MSG_DONTWAIT);
			ip6_h = (struct ip6_hdr*)(m_buffer + sizeof(struct ethhdr));
			switch(ip6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt){
				case 4://ipv4 in ipv6
					#ifdef DEBUG_INFO
					printf(GREEN"In encapslation mode, IPv4 in IPv6\n"NORMAL);
					#endif
					r = encapslation_mode(m_buffer, frm_len);
					if(r== -1){
						printf("encapslation send fail\n");
					}
					break;
				case 0:
					igmp_hdr = (struct igmphdr *)(m_buffer + 14 + 40);
					if(igmp_hdr->type == 58){
						handle_icmpv6(m_igmp_fd, igmp_addr, m_buffer);
						printf("icmpv6 packet received.\n");
					}else{
						printf("Drop hop by hop packet...\n");
					}
					break;
				case 58://ICMPv6
					if(handle_icmpv6(m_igmp_fd, igmp_addr, m_buffer) == -1){
						printf("handle_icmp error!\n");
						return -1;
					}
					break;
				case 17://UDP
					if(trans_mode ==1){
						#ifdef DEBUG_INFO
						printf(GREEN"In translation mode\n"NORMAL);
						#endif
						r = translation_mode(m_buffer, frm_len);
						if(r== -1){
							printf("translation send fail\n");
						}
					}
					else{
						#ifdef DEBUG_INFO
						printf(GREEN"In encapsulation mode, UDP\n"NORMAL);
						#endif
						r = encapslation_mode(m_buffer, frm_len);
						if(r== -1){
							printf("encapslation send fail\n");
						}
					}
					break;
				default : 
					printf(RED"\tNO need to deal with\n"NORMAL);
					break;
			}
			
		}
		

		if(FD_ISSET(multi_lis_igmp_fd4, &recv_fds)){

			#ifdef DEBUG_INFO
			printf(GREEN"\n\tigmp packet coming\n"NORMAL);
			#endif
			
			memset(m_buffer, 0, sizeof(m_buffer));
			frm_len = recv(multi_lis_igmp_fd4, m_buffer, 8192, MSG_DONTWAIT);
		
			ip_h = (struct iphdr*)(m_buffer + sizeof(struct ethhdr));

			if(ip_h->protocol == 2){
				printf(YELLOW"\n=============%d==============\n"NORMAL, i+1);
				printf("IP Packet from: %s\n",inet_ntoa(*(struct in_addr*)&ip_h->saddr));
				printf("--IP Packet To: %s\n",inet_ntoa(*(struct in_addr*)&ip_h->daddr));
				printf("---IP Protocol: %d (2 for igmp)\n",(ip_h->protocol));
				printf("-Buffer Length: %d bytes\n",frm_len);
				printf("-IP header Length: %d bytes\n", ip_h->ihl);
				if (inet_ntop(AF_INET, &(ip_h->saddr), src_addr, sizeof(src_addr)) <= 0) {
					perror("inet_ntop:");
					printf(RED"FD_ISSET: ERROR EXIT\n"NORMAL);
					return -1;
				}
				igmp_h = (struct igmp*)(m_buffer + sizeof(struct ethhdr) + (ip_h->ihl*4));
				
				igmpv2_rep_2_mld(igmp_h, src_addr);
			}
		}

		
	}
	

	
	
	return 0;
}

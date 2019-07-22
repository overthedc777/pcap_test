#include <pcap.h>
#include <stdio.h>

struct ethernet {
        u_int8_t ether_dhost[6]; /* Destination host address */
        u_int8_t ether_shost[6]; /* Source host address */
        u_int16_t ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct ip {
        u_int8_t ip_vhl;		/* version << 4 | header length >> 2 */
        u_int8_t ip_tos;		/* type of service */
        u_int16_t ip_len;		/* total length */
        u_int16_t ip_id;		/* identification */
        u_int16_t ip_off;		/* fragment offset field */
        u_int8_t ip_ttl;		/* time to live */
        u_int8_t ip_p;		/* protocol */
        u_int16_t ip_sum;		/* checksum */
        u_int8_t ip_src[4];
        u_int8_t ip_dst[4]; /* source and dest address */
    };


    struct tcp {
        u_int16_t th_sport;	/* source port */
        u_int16_t th_dport;	/* destination port */
        u_int8_t th_seq[4];		/* sequence number */
        u_int8_t th_ack[4];		/* acknowledgement number */
        u_int8_t th_offx2;	/* data offset, rsvd */
        u_int8_t th_flags;
        u_int16_t th_win;		/* window */
        u_int16_t th_sum;		/* checksum */
        u_int16_t th_urp;		/* urgent pointer */
};
    struct data{
        u_int8_t data[10];
    };

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
struct ethernet *eth;

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    eth = (struct ethernet*)(packet);
    printf("\n");
    printf("Dest Mac:");
    for(int i=0; i<=5; i++){
    printf("%02X",eth->ether_dhost[i]);
    if(i!=5)
    {
        printf(":");
    }

    }
    printf("\n");
    printf("Sorc Mac:");
    for(int i=0; i<=5; i++){
    printf("%02X",eth->ether_shost[i]);
    if(i!=5)
    {
        printf(":");
    }

    }
  }

  pcap_close(handle);
  return 0;
}

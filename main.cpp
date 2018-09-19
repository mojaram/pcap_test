#include <pcap.h>
#include <stdio.h>

void dump(const u_char* p, int len){
  printf("Ethernet Header src mac : 0x%02x%02x%02x%02x%02x%02x \n", *p, *(p+1), *(p+2), *(p+3), *(p+4), *(p+5));
  printf("Ethernet Header dst mac : 0x%02x%02x%02x%02x%02x%02x \n", *(p+6), *(p+7), *(p+8), *(p+9), *(p+10), *(p+11));
  if((*(p+12) == 0x08) && (*(p+13) == 0x00)) { // IP
    printf("IP Header src ip : 0x%02x%02x%02x%02x \n", *(p+26), *(p+27), *(p+28), *(p+29));
    printf("IP Header dst ip : 0x%02x%02x%02x%02x \n", *(p+30), *(p+31), *(p+32), *(p+33));
    int ilen;
    ilen = (*(p+16)) * 256 + (*(p+17));
    if(*(p+23) == 0x06) { // TCP
      printf("TCP Header src port : 0x%02x%02x \n", *(p+34), *(p+35));
      printf("TCP Header dst port : 0x%02x%02x \n", *(p+36), *(p+37));
      printf("Payload(Data) hexa decimal value : \n");
      for(int i = 54; (i < 54 + ilen - 20) && (i < 86); i++) {
        printf("%02x ", *(p+54));
        p++;
      }
      printf("\n");
    }
  }
  printf("\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

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
  printf("packet capture\n");
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    // printf("%u bytes captured\n", header->caplen);
    dump(packet, header->caplen);
  }

  pcap_close(handle);
  return 0;
}
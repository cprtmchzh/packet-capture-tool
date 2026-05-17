#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#define ETHER_ADDR_LEN 6 // MAC 주소 길이: 6바이트
#define TCP_ADDR_LEN 2   // TCP 포트 번호 길이: 2바이트
#define ETH_HDR_LEN 14   // Ethernet 헤더 길이: 14바이트

// 프로그램 사용법 출력 함수
void usage()
{
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

// 실행 인자로 받은 네트워크 인터페이스 이름을 저장하는 구조체
typedef struct
{
    char *dev_;
} Param;

// Ethernet 헤더 구조체
struct ethernet_hdr
{
    u_int8_t ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC 주소
    u_int8_t ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC 주소
    u_int8_t ether_type[2];               // 상위 프로토콜 타입
};

// TCP 헤더 구조체
struct tcp_hdr
{
    u_int8_t th_sport[TCP_ADDR_LEN]; // 출발지 포트 번호
    u_int8_t th_dport[TCP_ADDR_LEN]; // 목적지 포트 번호
    u_int8_t th_hl[10];
};

// 전역 파라미터 변수
Param param = {
    .dev_ = NULL};

// 명령행 인자를 파싱하는 함수
bool parse(Param *param, int argc, char *argv[])
{
    // 인터페이스 이름 하나만 입력받아야 함
    if (argc != 2)
    {
        usage();
        return false;
    }

    // 사용자가 입력한 인터페이스 이름 저장
    param->dev_ = argv[1];
    return true;
}

// 캡처한 패킷을 분석하고 출력하는 함수
void packet_capture(const struct pcap_pkthdr *header, const u_char *packet)
{
    // 패킷의 시작 부분을 Ethernet 헤더로 해석
    struct ethernet_hdr *eth = (struct ethernet_hdr *)packet;

    // Ethernet Type 확인
    uint16_t ether_type = eth->ether_type[0] << 8 | eth->ether_type[1];

    // IPv4 패킷이 아니면 출력하지 않고 종료
    if (ether_type != 0x0800)
        return;

    // Ethernet 헤더 바로 뒤부터 IP 헤더 시작
    const uint8_t *ip = packet + ETH_HDR_LEN;

    // IPv4 헤더의 첫 번째 바이트 구조:
    uint8_t ip_hl = (ip[0] & 0x0F) * 4;

    // IPv4 헤더의 9번째 인덱스에는 상위 프로토콜 번호가 들어있다.
    // TCP는 프로토콜 번호 6이다.
    uint8_t protocol = ip[9];

    // TCP 패킷이 아니면 출력하지 않고 종료
    if (protocol != 6)
        return;

    // TCP 헤더 시작 위치 = Ethernet 헤더 길이 + IP 헤더 길이
    struct tcp_hdr *tcp = (struct tcp_hdr *)(packet + ETH_HDR_LEN + ip_hl);

    // TCP 헤더 길이 계산
    uint8_t tcp_hl = (tcp->th_hl[8] >> 4) * 4;

    // Payload 시작 위치 = Ethernet 헤더 + IP 헤더 + TCP 헤더
    const uint8_t *payload = packet + ETH_HDR_LEN + ip_hl + tcp_hl;

    // Ethernet 헤더 정보 출력
    printf("==========Ethernet Header==========\n");
    printf("Src Mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Dst Mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    // IP 헤더 정보 출력
    printf("==========IP Header==========\n");
    printf("Src IP : %d.%d.%d.%d\n", ip[12], ip[13], ip[14], ip[15]);
    printf("Dst IP : %d.%d.%d.%d\n", ip[16], ip[17], ip[18], ip[19]);

    // TCP 헤더 정보 출력
    printf("==========TCP Header==========\n");
    printf("Src Port : %u\n", tcp->th_sport[0] << 8 | tcp->th_sport[1]);
    printf("Dst Port : %u\n", tcp->th_dport[0] << 8 | tcp->th_dport[1]);

    // Payload 출력
    printf("==========Payload==========\n");
    if (header->caplen > payload - packet)
    {
        // Payload 길이 계산
        int payload_len = header->caplen - (payload - packet);

        // Payload 앞 20바이트까지만 16진수로 출력
        for (int i = 0; i < 20 && i < payload_len; i++)
        {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    }
    else
    {
        printf("No Data\n");
    }

    printf("\n");
}

int main(int argc, char *argv[])
{
    // 명령행 인자 파싱
    if (!parse(&param, argc, argv))
        return -1;

    // pcap 오류 메시지를 저장할 버퍼
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

    // pcap 핸들 생성 실패 시 종료
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    // 계속해서 패킷을 캡처하는 반복문
    while (true)
    {
        struct pcap_pkthdr *header; // 캡처된 패킷의 메타데이터
        const u_char *packet;       // 실제 패킷 데이터

        int res = pcap_next_ex(pcap, &header, &packet);

        // timeout이면 다음 패킷을 기다림
        if (res == 0)
            continue;

        // 오류 또는 캡처 종료 시 반복문 종료
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // 캡처한 패킷 분석 및 출력
        packet_capture(header, packet);
    }

    // pcap 핸들 닫기
    pcap_close(pcap);
}
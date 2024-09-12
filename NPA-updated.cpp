#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

class PacketAnalyzer {
private:
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        PacketAnalyzer* analyzer = reinterpret_cast<PacketAnalyzer*>(user_data);
        analyzer->analyze_packet(pkthdr, packet);
    }

    void analyze_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        std::cout << "\n=== New Packet Captured ===\n";
        std::cout << "Packet length: " << pkthdr->len << " bytes\n";

        // Ethernet header
        struct ether_header *eth_header = (struct ether_header *) packet;
        std::cout << "Ethernet type: " << ntohs(eth_header->ether_type) << std::endl;

        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            const u_char *ip_packet = packet + sizeof(struct ether_header);
            analyze_ip_packet(ip_packet);
        }
    }

    void analyze_ip_packet(const u_char *ip_packet) {
        struct ip *ip_header = (struct ip *)ip_packet;

        std::cout << "IP Header:\n";
        std::cout << "  Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "  Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;
        
        switch(ip_header->ip_p) {
            case IPPROTO_TCP:
                analyze_tcp_packet(ip_packet + (ip_header->ip_hl << 2));
                break;
            case IPPROTO_UDP:
                analyze_udp_packet(ip_packet + (ip_header->ip_hl << 2));
                break;
            case IPPROTO_ICMP:
                analyze_icmp_packet(ip_packet + (ip_header->ip_hl << 2));
                break;
            default:
                std::cout << "  Protocol: Unknown\n";
        }
    }

    void analyze_tcp_packet(const u_char *tcp_packet) {
        struct tcphdr *tcp_header = (struct tcphdr *)tcp_packet;
        
        std::cout << "TCP Header:\n";
        std::cout << "  Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "  Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
        std::cout << "  Sequence Number: " << ntohl(tcp_header->th_seq) << std::endl;
        std::cout << "  Acknowledgment Number: " << ntohl(tcp_header->th_ack) << std::endl;
        std::cout << "  Flags:";
        if (tcp_header->th_flags & TH_FIN) std::cout << " FIN";
        if (tcp_header->th_flags & TH_SYN) std::cout << " SYN";
        if (tcp_header->th_flags & TH_RST) std::cout << " RST";
        if (tcp_header->th_flags & TH_PUSH) std::cout << " PSH";
        if (tcp_header->th_flags & TH_ACK) std::cout << " ACK";
        if (tcp_header->th_flags & TH_URG) std::cout << " URG";
        std::cout << std::endl;
    }

    void analyze_udp_packet(const u_char *udp_packet) {
        struct udphdr *udp_header = (struct udphdr *)udp_packet;
        
        std::cout << "UDP Header:\n";
        std::cout << "  Source Port: " << ntohs(udp_header->uh_sport) << std::endl;
        std::cout << "  Destination Port: " << ntohs(udp_header->uh_dport) << std::endl;
        std::cout << "  Length: " << ntohs(udp_header->uh_ulen) << std::endl;
    }

    void analyze_icmp_packet(const u_char *icmp_packet) {
        struct icmp *icmp_header = (struct icmp *)icmp_packet;
        
        std::cout << "ICMP Header:\n";
        std::cout << "  Type: " << static_cast<int>(icmp_header->icmp_type) << std::endl;
        std::cout << "  Code: " << static_cast<int>(icmp_header->icmp_code) << std::endl;
    }

public:
    PacketAnalyzer() : handle(nullptr) {}

    bool init(const char* device) {
        handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "Couldn't open device " << device << ": " << errbuf << std::endl;
            return false;
        }
        return true;
    }

    void start_capture() {
        if (handle == nullptr) {
            std::cerr << "Packet capture not initialized." << std::endl;
            return;
        }
        
        std::cout << "Starting packet capture. Press Ctrl+C to stop.\n";
        pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(this));
    }

    ~PacketAnalyzer() {
        if (handle != nullptr) {
            pcap_close(handle);
        }
    }
};

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }

    PacketAnalyzer analyzer;
    if (!analyzer.init(argv[1])) {
        return 1;
    }

    analyzer.start_capture();

    return 0;
}
#include <iostream>
#include <bits/stdc++.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <cstring>
#include <unistd.h>
#include <chrono>
#include <netinet/ip.h>
#include <netdb.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wwritable-strings"

using namespace std;
using namespace std::chrono;

void help() {
    cout << "Usage: ./icmpups" << " -d <destination ip>" << endl << endl;
    cout << "Also you can use: " << endl <<
         "-h <hops>" << endl <<
         "-d <destination ip>" << endl <<
         "-rt <response_timeout>" << endl;
}

pid_t ppid = getppid();

void catch_ctrl_c(int signal);

void traceroute(char *ip, int max_hops, int response_timeout);

uint16_t checksum(const void *data, size_t len);

char *dns(char *url){
    struct hostent *he;
    struct in_addr **addr_list;

    he = gethostbyname(url);

    if (he == nullptr) {
        herror("gethostbyname");

        cout << "1. Check your Network Connection. " << endl
        << "2. Check your DNS in /etc/resolv.conf - may be its unreachable" << endl
        << "3. You can disable DNS using -dns disable" << endl;

        return "0";
    }

    cout << "Official name: " << he->h_name << endl;
    cout << "IP address: " << inet_ntoa(*(struct in_addr *) he->h_addr) << endl;
    cout << "All addresses: ";

    addr_list = (struct in_addr **) he->h_addr_list;
    for (int i = 0; addr_list[i] != nullptr; i++) {
        cout << "   " << inet_ntoa(*addr_list[i]);
    }

    cout << endl;

    char ip[1024];
    strcpy(ip, inet_ntoa(*(struct in_addr *) he->h_addr));
    return ref(ip);
}

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    union {
        struct {
            uint16_t identifier;
            uint16_t sequence;
            uint64_t payload;
        } echo;

        struct ICMP_PACKET_POINTER_HEADER {
            uint8_t pointer;
        } pointer;

        struct ICMP_PACKET_REDIRECT_HEADER {
            uint32_t gatewayAddress;
        } redirect;
    } meta;
};

uint16_t checksum(const void *data, size_t len) {
    auto p = reinterpret_cast<const uint16_t *>(data);

    uint32_t sum = 0;

    if (len & 1) {
        sum = reinterpret_cast<const uint8_t *>(p)[len - 1];
    }

    len /= 2;

    while (len--) {
        sum += *p++;
        if (sum & 0xffff0000) {
            sum = (sum >> 16) + (sum & 0xffff);
        }
    }

    return static_cast<uint16_t>(~sum);
}


int main(int argc, char **argv) {
    cout << endl << endl;
    cout << "'####::'######::'##::::'##:'########::'##::::'##:'########:::'######::\n"
            ". ##::'##... ##: ###::'###: ##.... ##: ##:::: ##: ##.... ##:'##... ##:\n"
            ": ##:: ##:::..:: ####'####: ##:::: ##: ##:::: ##: ##:::: ##: ##:::..::\n"
            ": ##:: ##::::::: ## ### ##: ########:: ##:::: ##: ########::. ######::\n"
            ": ##:: ##::::::: ##. #: ##: ##.....::: ##:::: ##: ##.....::::..... ##:\n"
            ": ##:: ##::: ##: ##:.:: ##: ##:::::::: ##:::: ##: ##::::::::'##::: ##:\n"
            "'####:. ######:: ##:::: ##: ##::::::::. #######:: ##::::::::. ######::\n"
            "....:::......:::..:::::..::..::::::::::.......:::..::::::::::......:::";
    cout << endl << endl;

    if (argc < 2) {
        help();
        return 0;
    }

    char *url, *ip;
    char *dns_used = "enable";
    int max_hops = 30;
    int response_timeout = 1;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            help();
            return 0;
        }

        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--destination") == 0) {
            url = argv[i + 1];
            i += 1;
        }

        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--hops") == 0) {
            max_hops = atoi(argv[i + 1]);
            i += 1;
        }

        if (strcmp(argv[i], "-rt") == 0 || strcmp(argv[i], "--response_timeout") == 0) {
            response_timeout = atoi(argv[i + 1]);
            i += 1;
        }
        if(strcmp(argv[i], "-dns") == 0 || strcmp(argv[i], "--dns") == 0){
            dns_used = argv[i + 1];
        }
    }

    if(strcmp(dns_used, "enable") == 0){
        ip = dns(url);

        if(strcmp(ip, "0") == 0){
            cout << "Invalid IP, try again" << endl;
            return 0;
        }
    } else {
        ip = url;
    }

    signal(SIGINT, catch_ctrl_c);

    traceroute(ip, max_hops, response_timeout);

    return 0;
}

int sock;

void traceroute(char *ip, int max_hops, int response_timeout) {
    cout << "Traceroute to " << "\033[1;35m" << ip << "\033[0m" << endl;
    cout << "Max hops: " << "\033[1;35m" << max_hops << "\033[0m" << endl << endl;

    struct sockaddr_in in_addr{};

    in_addr.sin_family = AF_INET;
    in_addr.sin_addr.s_addr = inet_addr(ip);
    in_addr.sin_port = htons(0);

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sock < 0) {
        perror("socket error");
        return;
    }

    struct icmp_header icmp_packet{};

    for (int i = 0; i < max_hops; i++) {
        icmp_packet.type = 8;
        icmp_packet.code = 0;
        icmp_packet.checksum = 0;
        icmp_packet.meta.echo.identifier = ppid;
        icmp_packet.meta.echo.sequence = i;
        icmp_packet.meta.echo.payload = 0b101101010110100101; // random binary data
        icmp_packet.checksum = checksum(&icmp_packet, sizeof(icmp_packet));

        int ttl = i + 1;

        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        auto send_flag = sendto(sock, &icmp_packet, sizeof(icmp_packet), 0, (struct sockaddr *) &in_addr,
                                socklen_t(sizeof(in_addr)));

        if (send_flag < 0) {
            perror("send error");
            return;
        }

        struct iphdr ip_response_header{};

        struct timeval tv{};
        tv.tv_sec = response_timeout;
        tv.tv_usec = 0;

        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        auto data_length_byte = recv(sock, &ip_response_header, sizeof(ip_response_header), 0);

        if (data_length_byte == -1) {
            cout << ttl << "\033[1;35m" << " * * *" << "\033[0m" << endl;
            continue;
        }

        struct sockaddr_in src_addr{};
        src_addr.sin_addr.s_addr = ip_response_header.saddr;

        cout << ttl << " " << "\033[1;35m" <<  inet_ntoa(src_addr.sin_addr) << "\033[0m" << endl;

        if (strcmp(inet_ntoa(src_addr.sin_addr), ip) == 0) {
            cout << endl << "\033[1;35m" << ttl << "\033[0m" << " hops between you and " << ip << endl;
            break;
        }
    }
}

void catch_ctrl_c(int signal) {
    close(sock);
    cout << endl << "\033[1;35m" << "Socket closed. Exiting..." << "\033[0m" << endl << endl;
    exit(signal);
}
#pragma clang diagnostic pop
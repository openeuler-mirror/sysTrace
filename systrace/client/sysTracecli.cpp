#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/sysTrace_socket"

void print_help() {
    std::cout << "Usage: sysTrace_client <command> [args]\n"
              << "Commands:\n"
              << "  set <level>=<true|false> - Enable/disable dump level\n"
              << "                            (levels: L0, L1, L2, L3)\n"
              << "  interval <level>=<value> - Set dump interval in minutes\n"
              << "                            (levels: L1, L2, L3)\n"
              << "  print [level|all]        - Print current settings\n"
              << "                            (levels: L0, L1, L2, L3, all)\n\n"
              << "Examples:\n"
              << "  sysTrace_cli set L1=true\n"
              << "  sysTrace_cli interval L1=10\n"
              << "  sysTrace_cli print all\n";
}

int main(int argc, char *argv[])
{
    if (argc < 2 || std::string(argv[1]) == "help")
    {
        print_help();
        return 0;
    }

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("connect");
        close(sockfd);
        return 1;
    }

    std::string command;
    if (std::string(argv[1]) == "print")
    {
        command = "print";
        if (argc >= 3)
            command += std::string(" ") + argv[2];
    }
    else if (argc >= 3)
    {
        command = std::string(argv[1]) + " " + argv[2];
    }
    else
    {
        std::cerr << "Invalid command format\n";
        close(sockfd);
        return 1;
    }

    if (write(sockfd, command.c_str(), command.size()) == -1)
    {
        perror("write");
        close(sockfd);
        return 1;
    }

    char buffer[1024];
    ssize_t n = read(sockfd, buffer, sizeof(buffer) - 1);
    if (n > 0)
    {
        buffer[n] = '\0';
        std::cout << buffer;
    }

    close(sockfd);
    return 0;
}
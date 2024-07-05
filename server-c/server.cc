#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>  // For close()
#include <thread>    // For std::thread
#include <vector>    // For storing threads

void handle_client(int client_sockfd) {
    char buffer[256];
    ssize_t bytes_received;

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        bytes_received = recv(client_sockfd, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("Client disconnected.\n");
            } else {
                perror("recv error");
            }
            break;
        }

        buffer[bytes_received] = '\0';
        printf("Received from client: %s", buffer);

        // Remove newline character if present
        while (bytes_received > 0 && (buffer[bytes_received - 1] == '\n' || buffer[bytes_received -1] == '\r')) {
            buffer[--bytes_received] = '\0';
        }
        if (strcmp(buffer, "exit") == 0 || strcmp(buffer, "quit") == 0) {
            printf("Client requested to exit.\n");
            break;
        }
    }

    close(client_sockfd);
}

int main() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        std::cerr << "Error setting up the socket" << std::endl;
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8080),
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
        .sin_zero = {0}
    };

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        std::cerr << "Error setting up the bind call" << std::endl;
        return -1;
    }

    if (listen(sockfd, 5) == -1) {
        std::cerr << "Error calling listen" << std::endl;
        return -1;
    }

    std::vector<std::thread> threads;  // Optionally store threads if needed

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sockfd == -1) {
            std::cerr << "Error calling accept" << std::endl;
            continue;  // Continue accepting other connections
        }

        std::cout << "Connection accepted from " << inet_ntoa(client_addr.sin_addr) << std::endl;
        
        threads.push_back(std::thread([client_sockfd]() {
            handle_client(client_sockfd);
        }));
    }

    // Optionally join threads (usually not done in a server that runs indefinitely)
    for (auto& th : threads) {
        if (th.joinable()) th.join();
    }

    close(sockfd);  // Close the listening socket
    return 0;
}


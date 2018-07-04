#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <spawn.h>
#include <Foundation/Foundation.h>
#include <stdlib.h>

#define BUFSIZE 1024

#define JAILBREAKD_COMMAND_ENTITLE 1
#define JAILBREAKD_COMMAND_PLATFORMIZE 2
#define JAILBREAKD_COMMAND_FIXUP_SETUID 6

struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID {
    uint8_t Command;
    int32_t Pid;
};

int main(int argc, const char* argv[], const char* envp[]) {
    
    int sockfd, portno, n;
    int serverlen;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char buf[BUFSIZE];
    
    hostname = "127.0.0.1";
    portno = 5;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        printf("ERROR opening socket\n");
    
    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        exit(0);
    }
    
    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);
    
    /* get a message from the user */
    bzero(buf, BUFSIZE);
    
    
    pid_t pd;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED); //this flag will make the created process stay frozen until we send the CONT signal. This so we can platformize it before it launches.
    
    NSString *reallaunchctl = [NSString stringWithFormat:@"%@/launchctl_", [[NSBundle mainBundle] bundlePath]];
    
    int rv = posix_spawn(&pd, [reallaunchctl UTF8String], NULL, &attr, argv, envp);
    
    struct JAILBREAKD_ENTITLE_PID entitlePacket;
    entitlePacket.Pid = pd;
    entitlePacket.Command = JAILBREAKD_COMMAND_PLATFORMIZE;
    
    memcpy(buf, &entitlePacket, sizeof(struct JAILBREAKD_ENTITLE_PID));
    
    serverlen = sizeof(serveraddr);
    n = sendto(sockfd, buf, sizeof(struct JAILBREAKD_ENTITLE_PID), 0, (const struct sockaddr *)&serveraddr, serverlen);
    if (n < 0) {
        printf("Error in sendto\n");
        return -1;
    }
    
    kill(pd, SIGCONT); //continue
    
    int a;
    waitpid(pd, &a, 0);
    
    return rv;
}

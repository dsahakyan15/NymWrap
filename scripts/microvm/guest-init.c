/* NymWrap shadow guest PID 1. No host filesystem or Ethernet device exists.
 * This is trusted plumbing, never generated from model output. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/vm_sockets.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(void) { reboot(RB_AUTOBOOT); _exit(125); }
static void check(int ok) { if (!ok) die(); }
static int host(unsigned port) {
    int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_vm address = {.svm_family=AF_VSOCK, .svm_cid=2, .svm_port=port};
    if (fd < 0 || connect(fd, (void *)&address, sizeof(address))) { if(fd>=0)close(fd); return -1; }
    return fd;
}
static void relay(int a, int b) {
    struct pollfd p[2]={{a,POLLIN,0},{b,POLLIN,0}};
    char buffer[16384];
    for (;;) {
        if (poll(p,2,30000)<=0) break;
        for (int i=0;i<2;i++) if(p[i].revents) {
            ssize_t n=read(p[i].fd,buffer,sizeof(buffer));
            if(n<=0) return;
            for(ssize_t offset=0;offset<n;) {
                ssize_t sent=write(p[1-i].fd,buffer+offset,(size_t)(n-offset));
                if(sent<=0)return;
                offset+=sent;
            }
        }
    }
}
static void proxy(int server) {
    for(;;) {
        int client=accept4(server,NULL,NULL,SOCK_CLOEXEC);
        if(client<0)_exit(125);
        pid_t pid=fork();
        if(pid==0) {close(server);int api=host(8000);if(api>=0)relay(client,api);_exit(0);}
        close(client);
        while(waitpid(-1,NULL,WNOHANG)>0) {}
    }
}
/* Synthetic CI probe: same kernel and identity as the agent. */
static int probe(void) {
    char name[64], cwd[64];
    if(gethostname(name,sizeof(name)) || strcmp(name,"localhost") ||
       !getcwd(cwd,sizeof(cwd)) || strcmp(cwd,"/work") ||
       getuid()!=1000 || getgid()!=1000 || strcmp(getenv("TZ"),"UTC") ||
       getenv("NW_MICROVM_HOST_CANARY") || strcmp(getenv("HOME"),"/home/user") ||
       strcmp(getenv("LANG"),"C.UTF-8") || strcmp(getenv("LC_ALL"),"C.UTF-8") ||
       access("/sys",F_OK)==0 || access("/host",F_OK)==0) return 10;
    FILE *f=fopen("/etc/machine-id","r");
    if(!f || !fgets(name,sizeof(name),f) || strcmp(name,"00000000000000000000000000000001\n")) return 11;
    fclose(f);
    f=fopen("/work/fixture","r");
    if(!f || !fgets(name,sizeof(name),f) || strcmp(name,"synthetic-project-only"))return 19;
    fclose(f);
    pid_t shell=fork();
    if(shell<0)return 18;
    if(shell==0) {execl("/bin/sh","sh","-c","test \"$(pwd)\" = /work && test \"$(hostname)\" = localhost && test \"$(id -u)\" = 1000 && test \"$(date +%Z)\" = UTC",(char *)NULL);_exit(127);}
    int shell_status;if(waitpid(shell,&shell_status,0)!=shell || !WIFEXITED(shell_status) || WEXITSTATUS(shell_status))return 18;
    for(int v6=0;v6<2;v6++) for(int udp=0;udp<2;udp++) {
        int s=socket(v6?AF_INET6:AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0);
        if(s<0)continue;
        struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(udp?53:443)};
        struct sockaddr_in6 b={.sin6_family=AF_INET6,.sin6_port=htons(udp?53:443)};
        inet_pton(AF_INET,"192.0.2.1",&a.sin_addr);
        inet_pton(AF_INET6,"2001:db8::1",&b.sin6_addr);
        int result=connect(s,v6?(void*)&b:(void*)&a,v6?sizeof(b):sizeof(a));
        close(s);
        if(result==0)return 12;
    }
    struct addrinfo *resolved=NULL;
    if(!getaddrinfo("microvm-canary.invalid",NULL,NULL,&resolved)) {freeaddrinfo(resolved);return 17;}
    int s=socket(AF_UNIX,SOCK_STREAM,0);
    struct sockaddr_un a={.sun_family=AF_UNIX,.sun_path="/run/nymwrap/api.sock"};
    if(s<0 || connect(s,(void*)&a,sizeof(a)))return 13;
    const char body[]="{\"model\":\"nw/local/default\",\"messages\":[{\"role\":\"user\",\"content\":\"synthetic-microvm-canary\"}]}";
    char request[512];
    int length=snprintf(request,sizeof(request),"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",sizeof(body)-1,body);
    if(length<=0 || length>=(int)sizeof(request) || write(s,request,(size_t)length)!=length)return 14;
    char answer[1024];size_t count=0;ssize_t n;
    while(count<sizeof(answer)-1 && (n=read(s,answer+count,sizeof(answer)-1-count))>0)count+=(size_t)n;
    answer[count]=0;close(s);
    if(!strstr(answer,"synthetic-nymwrap-answer"))return 15;
    f=fopen("/work/ephemeral-result","w");if(!f)return 16;fputs("synthetic-only",f);fclose(f);
    return 0;
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--probe"))return probe();
    check(getpid()==1);
    umask(077);
    struct rlimit zero={0,0};check(!setrlimit(RLIMIT_CORE,&zero));
    check(!mount("proc","/proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL));
    check(!mount("devtmpfs","/dev","devtmpfs",MS_NOSUID|MS_NOEXEC,NULL));
    check(!sethostname("localhost",9));
    check(!chdir("/work"));
    check(!chown("/work",1000,1000));
    check(!chown("/home/user",1000,1000));
    int server=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    struct sockaddr_un address={.sun_family=AF_UNIX,.sun_path="/run/nymwrap/api.sock"};
    check(server>=0 && !bind(server,(void*)&address,sizeof(address)) && !listen(server,8));
    check(!chown(address.sun_path,1000,1000));
    pid_t proxy_pid=fork();check(proxy_pid>=0);
    if(proxy_pid==0) { check(!setgroups(0,NULL) && !setgid(1000) && !setuid(1000));proxy(server); }
    close(server);
    FILE *f=fopen("/run/argv","rb");check(f!=NULL);
    char bytes[65536];size_t n=fread(bytes,1,sizeof(bytes),f);fclose(f);
    check(n>0 && n<sizeof(bytes) && bytes[n-1]==0);
    char *command[257];size_t count=0;
    for(size_t i=0;i<n;) {check(count<256);command[count++]=bytes+i;i+=strlen(bytes+i)+1;}
    command[count]=NULL;
    int output=host(8001);check(output>=0);
    pid_t child=fork();check(child>=0);
    if(child==0) {
        check(!setgroups(0,NULL) && !setgid(1000) && !setuid(1000));
        check(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        check(dup2(output,1)==1 && dup2(output,2)==2);
        int input=open("/dev/null",O_RDONLY);check(input>=0 && dup2(input,0)==0);
        clearenv();
        const char *env[]={"PATH=/bin", "HOME=/home/user", "USER=user", "LOGNAME=user",
            "TZ=UTC", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "NYMWRAP_LANE=shadow",
            "NYMWRAP_API_SOCKET=/run/nymwrap/api.sock", "OPENAI_BASE_URL=http://localhost/v1", "OPENAI_API_KEY=local",NULL};
        execve(command[0],command,(char *const *)env);_exit(127);
    }
    close(output);int status;
    check(waitpid(child,&status,0)==child);
    int result=WIFEXITED(status)?WEXITSTATUS(status):125;
    int report=host(8002);check(report>=0);
    unsigned char message[5]={'N','W','V','M',(unsigned char)result};
    check(write(report,message,sizeof(message))==sizeof(message));close(report);
    die();
}

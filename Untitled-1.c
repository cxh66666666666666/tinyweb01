#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <sys/stat.h>
#include <fcntl.h>

#pragma comment(lib, "ws2_32.lib")

#define MAXLINE 8192
#define MAXBUF 8192

typedef struct {
    SOCKET fd;
    char *buf;
    int buf_len;
    int read_ptr;
} rio_t;

void Rio_readinitb(rio_t *rp, SOCKET fd);
size_t Rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen);
size_t Rio_writen(SOCKET fd, void *usrbuf, size_t n);
SOCKET Open_listenfd(char *port);
SOCKET Accept(SOCKET listenfd, struct sockaddr *addr, int *addrlen);
void Close(SOCKET fd);
HANDLE Open(const char *filename, int flags, int mode);

void doit(SOCKET fd);
void read_requesthdrs(rio_t *rp);
int parse_uri(char *uri, char *filename, char *cgiargs);
void serve_static(SOCKET fd, char *filename, int filesize);
void get_filetype(char *filename, char *filetype);
void serve_dynamic(SOCKET fd, char *filename, char *cgiargs);
void clienterror(SOCKET fd, char *cause, char *errnum, char *shortmsg, char *longmsg);

int main(int argc, char **argv)
{
    SOCKET listenfd, connfd;
    char hostname[MAXLINE], port[MAXLINE];
    int clientlen;
    struct sockaddr_in clientaddr;

    /* 初始化Winsock */
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        exit(1);
    }

    /* 检查命令行args */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(1);
    }

    /* 循环接收来自客户端的连接 */
    listenfd = Open_listenfd(argv[1]);
    if (listenfd == INVALID_SOCKET) {
        fprintf(stderr, "Failed to create listen socket\n");
        WSACleanup();
        exit(1);
    }
    
    printf("Server listening on port %s\n", argv[1]);
    
    while (1) {
        clientlen = sizeof(clientaddr);
        connfd = Accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
        if (connfd == INVALID_SOCKET) {
            fprintf(stderr, "Accept failed\n");
            continue;
        }
        
        /* 获取客户端信息 */
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientaddr.sin_addr), client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(clientaddr.sin_port);
        
        printf("接收来自（%s:%d）的连接\n", client_ip, client_port);
        doit(connfd);
        Close(connfd);
    }
    
    Close(listenfd);
    WSACleanup();
    return 0;
}

void doit(SOCKET fd)
{
    int is_static;
    struct _stat sbuf;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char filename[MAXLINE], cgiargs[MAXLINE];
    rio_t rio;

    /* 读取请求行和头部 */
    Rio_readinitb(&rio, fd);
    if (Rio_readlineb(&rio, buf, MAXLINE) <= 0) {
        return;
    }
    
    printf("请求头部：\n");
    printf("%s", buf);
    
    if (sscanf(buf, "%s %s %s", method, uri, version) != 3) {
        clienterror(fd, "Request", "400", "Bad Request", "Tiny无法解析请求");
        return;
    }
    
    if (strcasecmp(method, "GET") != 0) {
        clienterror(fd, method, "501", "执行失败", "Tiny无法执行此方法");
        return;
    }
    
    read_requesthdrs(&rio);

    /* 解析来自GET请求的URI */
    is_static = parse_uri(uri, filename, cgiargs);
    if (_stat(filename, &sbuf) < 0) {
        clienterror(fd, filename, "404", "未查找到", "Tiny未查找到此文件");
        return;
    }

    if (is_static) {
        /* 提供静态内容 */
        if (!(sbuf.st_mode & _S_IFREG) || !(sbuf.st_mode & _S_IREAD)) {
            clienterror(fd, filename, "403", "禁止的", "Tiny无法阅读此文件");
            return;
        }
        serve_static(fd, filename, sbuf.st_size);
    } else {
        /* 提供动态内容 */
        if (!(sbuf.st_mode & _S_IFREG) || !(sbuf.st_mode & _S_IEXEC)) {
            clienterror(fd, filename, "403", "禁止的", "Tiny无法运行此CGI程序");
            return;
        }
        serve_dynamic(fd, filename, cgiargs);
    }
}

/* 向客户端发送错误信息 */
void clienterror(SOCKET fd, char *cause, char *errnum, char *shortmsg, char *longmsg)
{
    char buf[MAXLINE], body[MAXBUF];

    /* 构建HTTP响应正文 */
    sprintf(body, "<html><title>Tiny Error</title>");
    sprintf(body, "%s<body bgcolor=""ffffff"">\r\n", body);
    sprintf(body, "%s%s: %s\r\n", body, errnum, shortmsg);
    sprintf(body, "%s<p>%s: %s\r\n", body, longmsg, cause);
    sprintf(body, "%s<hr><em>The Tiny Web server</em>\r\n", body);

    /* 打印HTTP的响应 */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-type: text/html\r\n");
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-length: %d\r\n\r\n", (int)strlen(body));
    Rio_writen(fd, buf, strlen(buf));
    Rio_writen(fd, body, strlen(body));
}

/* 读取请求头部 */
void read_requesthdrs(rio_t *rp)
{
    char buf[MAXLINE];
    
    Rio_readlineb(rp, buf, MAXLINE);
    while (strcmp(buf, "\r\n") != 0) {
        Rio_readlineb(rp, buf, MAXLINE);
        printf("%s", buf);
    }
    return;
}

/* TINY假设任何包含cgi-bin的URI都被认为是动态请求，反之则为静态 */
int parse_uri(char *uri, char *filename, char *cgiargs)
{
    char *ptr;

    /* 静态请求 */
    if (!strstr(uri, "cgi-bin")) {
        strcpy(cgiargs, "");
        strcpy(filename, ".");
        strcat(filename, uri);
        if (uri[strlen(uri) - 1] == '/')
            strcat(filename, "home.html");
        return 1;
    }
    /* 动态请求 */
    else {
        ptr = strchr(uri, '?');
        if (ptr) {
            strcpy(cgiargs, ptr + 1);
            *ptr = '\0';
        } else {
            strcpy(cgiargs, "");
        }
        strcpy(filename, ".");
        strcat(filename, uri);
        return 0;
    }
}

void serve_static(SOCKET fd, char *filename, int filesize)
{
    HANDLE srcfd;
    char *srcp, filetype[MAXLINE], buf[MAXBUF];
    DWORD bytesRead;

    get_filetype(filename, filetype);
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    sprintf(buf, "%sServer: Tiny Web Server\r\n", buf);
    sprintf(buf, "%sConnection: close\r\n", buf);
    sprintf(buf, "%sContent-length: %d\r\n", buf, filesize);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, filetype);
    Rio_writen(fd, buf, strlen(buf));
    printf("响应头部:\n");
    printf("%s", buf);

    srcfd = Open(filename, O_RDONLY, 0);
    if (srcfd == INVALID_HANDLE_VALUE) {
        return;
    }

    srcp = (char *)malloc(filesize + 1);
    if (!srcp) {
        CloseHandle(srcfd);
        return;
    }

    if (ReadFile(srcfd, srcp, filesize, &bytesRead, NULL)) {
        Rio_writen(fd, srcp, bytesRead);
    }
    
    free(srcp);
    CloseHandle(srcfd);
}

void get_filetype(char *filename, char *filetype)
{
    if (strstr(filename, ".html"))
        strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif"))
        strcpy(filetype, "image/gif");
    else if (strstr(filename, ".png"))
        strcpy(filetype, "image/png");
    else if (strstr(filename, ".jpg") || strstr(filename, ".jpeg"))
        strcpy(filetype, "image/jpeg");
    else if (strstr(filename, ".css"))
        strcpy(filetype, "text/css");
    else if (strstr(filename, ".js"))
        strcpy(filetype, "application/javascript");
    else
        strcpy(filetype, "text/plain");
}

void serve_dynamic(SOCKET fd, char *filename, char *cgiargs)
{
    char buf[MAXLINE];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    HANDLE hWritePipe, hReadPipe;

    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Server: Tiny Web Server\r\n");
    Rio_writen(fd, buf, strlen(buf));

    /* 创建管道用于与子进程通信 */
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;

    ZeroMemory(&pi, sizeof(pi));

    /* 设置环境变量 */
    char envVar[MAXLINE];
    sprintf(envVar, "QUERY_STRING=%s", cgiargs);
    putenv(envVar);

    /* 创建子进程 */
    if (CreateProcess(NULL, filename, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hWritePipe);
        
        /* 读取子进程输出并发送给客户端 */
        DWORD bytesRead;
        char buffer[4096];
        while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            Rio_writen(fd, buffer, bytesRead);
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hReadPipe);
}

/* 简化版的RIO函数实现 */
void Rio_readinitb(rio_t *rp, SOCKET fd)
{
    rp->fd = fd;
    rp->read_ptr = 0;
}

size_t Rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen)
{
    int n;
    char c, *bufp = usrbuf;

    for (n = 0; n < maxlen - 1; n++) {
        int result = recv(rp->fd, &c, 1, 0);
        if (result == 1) {
            *bufp++ = c;
            if (c == '\n') {
                n++;
                break;
            }
        } else if (result == 0) {
            break; /* EOF */
        } else {
            break; /* Error */
        }
    }
    *bufp = 0;
    return n;
}

size_t Rio_writen(SOCKET fd, void *usrbuf, size_t n)
{
    return send(fd, usrbuf, n, 0);
}

SOCKET Open_listenfd(char *port)
{
    SOCKET listenfd;
    struct addrinfo hints, *result, *rp;
    int optval = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &result) != 0) {
        return INVALID_SOCKET;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listenfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listenfd == INVALID_SOCKET)
            continue;

        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval));
        
        if (bind(listenfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        closesocket(listenfd);
    }

    freeaddrinfo(result);

    if (rp == NULL)
        return INVALID_SOCKET;

    if (listen(listenfd, SOMAXCONN) < 0) {
        closesocket(listenfd);
        return INVALID_SOCKET;
    }

    return listenfd;
}

SOCKET Accept(SOCKET listenfd, struct sockaddr *addr, int *addrlen)
{
    return accept(listenfd, addr, addrlen);
}

void Close(SOCKET fd)
{
    closesocket(fd);
}

HANDLE Open(const char *filename, int flags, int mode)
{
    return CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, 
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include<iostream>
#pragma comment(lib, "ws2_32.lib")  //加载 ws2_32.dll
#pragma warning(disable:4996)
using namespace std;


int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //创建套接字
    SOCKET sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    //向服务器发起请求
    struct sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr));  //每个字节都用0填充
    sockAddr.sin_family = PF_INET;
    //sockAddr.sin_addr.s_addr = inet_addr("74.235.92.151");
    sockAddr.sin_addr.s_addr = inet_addr("100.235.92.151");
    sockAddr.sin_port = htons(9999);
    int iResult;

    //iResult = connect(sock, (SOCKADDR*)&sockAddr, sizeof(SOCKADDR));
    do {
        Sleep(3000);
        iResult = connect(sock, (SOCKADDR*)&sockAddr, sizeof(SOCKADDR));
    } while (iResult != 0);
    while (true)//发送数据给服务器
    {
        Sleep(3000);
        char szBuffer[MAXBYTE] = { 0 };
        char* str = "whoami";
        send(sock, str, strlen(str) + sizeof(char), NULL);
        //recv(sock, szBuffer, MAXBYTE, NULL);
    }
    //关闭套接字
    closesocket(sock);

    //终止使用 DLL
    WSACleanup();

    system("pause");
    return 0;
}
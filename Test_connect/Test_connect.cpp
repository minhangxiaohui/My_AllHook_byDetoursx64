#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include<iostream>
#pragma comment(lib, "ws2_32.lib")  //���� ws2_32.dll
#pragma warning(disable:4996)
using namespace std;


int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //�����׽���
    SOCKET sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    //���������������
    struct sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr));  //ÿ���ֽڶ���0���
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
    while (true)//�������ݸ�������
    {
        Sleep(3000);
        char szBuffer[MAXBYTE] = { 0 };
        char* str = "whoami";
        send(sock, str, strlen(str) + sizeof(char), NULL);
        //recv(sock, szBuffer, MAXBYTE, NULL);
    }
    //�ر��׽���
    closesocket(sock);

    //��ֹʹ�� DLL
    WSACleanup();

    system("pause");
    return 0;
}
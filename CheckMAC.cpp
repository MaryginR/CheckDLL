#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#ifdef _WIN32
#include <stdio.h>
#include <Windows.h>
#include <Iphlpapi.h>
#include <Assert.h>

#pragma comment(lib, "iphlpapi.lib")
#else
#include <cstring>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <sys/socket.h>
#endif

#define CHECKMAC_EXPORTS
#include "CheckMAC.h"

struct MacVirtualMachinePair {
    const char* mac;
    const char* vm;
};

//Структура с mac-адресами и вир. машинами
MacVirtualMachinePair vmPairs[] = {
        { "00:05:69", "VMware" },
        { "00:0C:29", "VMware" },
        { "00:1C:14", "VMware" },

        { "08:00:27", "VirtualBox" },

        { "00:15:5D", "HyperV" },
        { "00:03:FF", "HyperV" },

        { "00:16:3E", "XenSource" },

        { "00:ca:fe", "Xen" },

        { "52:54:00", "KVM" }
};

// Функция, которая сравнивает MAC-адрес с массивом MacVirtualMachinePair и возвращает соответствующее название виртуальной машины
std::string check_mac(const char* mac) {

    int numPairs = sizeof(vmPairs) / sizeof(vmPairs[0]);

    for (int i = 0; i < numPairs; i++) {
        if (strncmp(mac, vmPairs[i].mac, 8) == 0) {
            return vmPairs[i].vm;
        }
    }

    return "host";
}

#ifdef _WIN32

std::string getVMonMAC() {
    IP_ADAPTER_INFO AdapterInfo;
    DWORD dwBufLen = sizeof(AdapterInfo);
    std::string mac_addr;

    if (GetAdaptersInfo(&AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
        // Если буфер недостаточен, выделяем новый
        PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(new char[dwBufLen]);
        if (pAdapterInfo != nullptr) {
            if (GetAdaptersInfo(pAdapterInfo, &dwBufLen) == NO_ERROR) {
                // Указатель на адаптеры
                PIP_ADAPTER_INFO pCurrentAdapter = pAdapterInfo;

                // Обходим в цикле все mac адреса и проверяем oui на наличие адресов виртуальных машин
                do {
                    if (pCurrentAdapter->AddressLength > 0 && pCurrentAdapter->Address != nullptr) {
                        std::stringstream ss;
                        for (unsigned int i = 0; i < pCurrentAdapter->AddressLength; ++i) {
                            ss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(pCurrentAdapter->Address[i]);
                            if (i < pCurrentAdapter->AddressLength - 1) {
                                ss << ":";
                            }
                        }
                        mac_addr = ss.str();
                        break;
                    }
                    pCurrentAdapter = pCurrentAdapter->Next;
                } while (pCurrentAdapter);
            }
            delete[] reinterpret_cast<char*>(pAdapterInfo);
        }
    }

    if (!mac_addr.empty()) {
        std::string check_result = check_mac(mac_addr.c_str());
        if (check_result == "host") {
            return "host";
        }
        else {
            return check_result;
        }
    }

    return "ERR";
}


#else


std::string getVMonMAC() {
    struct ifaddrs* ifaddr, * ifa;
    char mac_addr[18];

    if (getifaddrs(&ifaddr) != 0) {
        return "ERR";
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl* sdl = (struct sockaddr_dl*)ifa->ifa_addr;
            const unsigned char* macBytes = (unsigned char*)LLADDR(sdl);
            std::stringstream ss;
            for (int i = 0; i < sdl->sdl_alen; ++i) {
                ss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(macBytes[i]);
                if (i < sdl->sdl_alen - 1) {
                    ss << ":";
                }
            }
            std::strcpy(mac_addr, ss.str().c_str());

            std::string check_result = check_mac(mac_addr);
            if (check_result != "host") {
                freeifaddrs(ifaddr);
                return check_result;
            }
        }
    }

    freeifaddrs(ifaddr);
    return "host";
}

#endif
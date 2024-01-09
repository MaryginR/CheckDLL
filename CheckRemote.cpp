#include <iostream>
#include <string>
#include <vector>
#ifdef _WIN32
#include <Windows.h>
#include <Psapi.h>
#include <algorithm>
#else
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iterator>
#endif

#define CHECKREMOTE_EXPORTS
#include "CheckRemote.h"

#ifdef _WIN32

std::vector<std::string> GetProcessNamesMatchingSubstrings(const std::vector<std::string>& substrings)
{
    std::vector<std::string> matchingProcessNames;

    // Получение всех процессов
    DWORD processes[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
    {
        return matchingProcessNames;
    }

    // Получение количества процессов
    cProcesses = cbNeeded / sizeof(DWORD);

    // Перебор процессов
    for (DWORD i = 0; i < cProcesses; i++)
    {
        if (processes[i] != 0)
        {
            // Получение дескриптора процесса
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (hProcess)
            {
                // Получение имени процесса
                char szProcessName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, NULL, szProcessName, sizeof(szProcessName) / sizeof(char)))
                {
                    // Преобразование имени процесса к нижнему регистру
                    std::string processName(szProcessName);
                    std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

                    // Проверка совпадения с подстроками
                    for (const std::string& substring : substrings)
                    {
                        std::string lowercaseSubstring(substring);
                        std::transform(lowercaseSubstring.begin(), lowercaseSubstring.end(), lowercaseSubstring.begin(), ::tolower);

                        if (processName.find(lowercaseSubstring) != std::string::npos)
                        {
                            matchingProcessNames.push_back(szProcessName);
                            break;
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }

    return matchingProcessNames;
}

std::string CheckRemote()
{
    std::vector<std::string> programs = { 
        "teamviewer_service.exe", 
        "tv_w32.exe", 
        "anydesk.exe", 
        "ammyy-admin-server.exe", 
        "ruhost.exe", 
        "ruremote.exe", 
        "vncserver.exe", 
        "winvnc.exe", 
        "uvnc_service.exe", 
        "tvnserver.exe",
        "radminserver.exe",
        "g2m_service.exe",
        "zatray.exe",
        "SupRemoServer.exe",
        "stservice.exe",
    };

    std::vector<std::string> matchingProcessNames = GetProcessNamesMatchingSubstrings(programs);

    if (!matchingProcessNames.empty())
    {
        //std::cout << "Matching process names:" << std::endl;
        for (const std::string& processName : matchingProcessNames)
        {
            //std::cout << processName << std::endl;
            return processName;
        }
    }
    else
    {
        //std::cout << "No matching processes found." << std::endl;
        return "host";
    }

    return "host";
}

#else

std::vector<std::string> GetProcessNamesMatchingSubstrings(const std::vector<std::string>& substrings)
{
    std::vector<std::string> matchingProcessNames;

    // Выполнение команды ps -A
    FILE* pipe = popen("ps -A -o comm=", "r");
    if (!pipe)
    {
        return matchingProcessNames;
    }

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        // Удаление символа новой строки
        buffer[strcspn(buffer, "\n")] = '\0';

        std::string processName(buffer);

        // Проверка совпадения с подстроками
        for (const std::string& substring : substrings)
        {
            std::string lowercaseSubstring = substring;
            std::transform(lowercaseSubstring.begin(), lowercaseSubstring.end(), lowercaseSubstring.begin(), ::tolower);

            std::string lowercaseProcessName = processName;
            std::transform(lowercaseProcessName.begin(), lowercaseProcessName.end(), lowercaseProcessName.begin(), ::tolower);

            if (lowercaseProcessName.find(lowercaseSubstring) != std::string::npos)
            {
                matchingProcessNames.push_back(processName);
                break;
            }
        }
    }

    pclose(pipe);

    return matchingProcessNames;
}

std::string CheckRemote()
{
    std::vector<std::string> programs;
    programs.push_back("teamviewer_service");
    programs.push_back("tv_w32");
    programs.push_back("anydesk");
    programs.push_back("ammyy-admin-server");
    programs.push_back("ruhost");
    programs.push_back("ruremote");
    programs.push_back("winvnc");
    programs.push_back("uvnc_service");
    programs.push_back("tvnserver");
    programs.push_back("radminserver");
    programs.push_back("g2m_service");
    programs.push_back("zatray");
    programs.push_back("SupRemoServer");
    programs.push_back("stservice");

    std::vector<std::string> matchingProcessNames = GetProcessNamesMatchingSubstrings(programs);

    if (!matchingProcessNames.empty())
    {
        //std::cout << "Matching process names:" << std::endl;
        for (const std::string& processName : matchingProcessNames)
        {
            return processName;
        }
    }
    else
    {
        return "host";
    }

    return 0;
}

#endif
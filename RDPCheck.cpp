#include <Windows.h>

#define CHECKRDP_EXPORTS
#include "RDPCheck.h"

bool IsRDPConnection()
{
    // Получаем значение sessionname
    wchar_t* sessionName = nullptr;
    size_t bufferSize;
    if (_wdupenv_s(&sessionName, &bufferSize, L"sessionname") != 0 || sessionName == nullptr)
    {
        // Если не удалось получить доступ к переменной
        return false;
    }

    // Проверка есть ли RDP соединение
    bool isRemote = wcsncmp(sessionName, L"RDP", wcslen(L"RDP")) == 0;

    // Очищаем выделенную память
    free(sessionName);

    return isRemote;
}
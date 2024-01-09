#include <iostream>
#include <windows.h>
#include <string>

#define CHECKREG_EXPORTS 
#include "CheckReg.h"

struct VirtualMachineKeys
{
    std::wstring key;
    std::string name;
};

// Список виртуальных машин и соответствующие им ключи
VirtualMachineKeys virtualMachineKeys[] = {
    { L"HARDWARE\\ACPI\\FADT\\VBOX_",                  "VBOX" },
    { L"SOFTWARE\\innotek\\VirtualBox",                "VBOX" },
    { L"SOFTWARE\\Org.VirtualBox",                     "VBOX" },
    { L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", "VBOX" },

    { L"SOFTWARE\\Citrix\\XenTools",              "XenSource" },
    { L"SYSTEM\\ControlSet001\\Services\\xenvbd", "XenSource" },
    { L"SYSTEM\\ControlSet001\\Services\\xenvif", "XenSource" },

    { L"SYSTEM\\ControlSet001\\Services\\vmhgfs",  "VMware" },
    { L"SYSTEM\\ControlSet001\\Services\\vmmouse", "VMware" },
    { L"SYSTEM\\ControlSet001\\Services\\vmtray",  "VMware" },
    //{ L"SOFTWARE\\VMware, Inc.", "VMware"},

    { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Hyper-V",   "HyperV" },
    { L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "HyperV" },

    { L"SOFTWARE\\KVM",             "KVM" },
    { L"SOFTWARE\\Red Hat\\VirtIO", "KVM" },

    { L"SOFTWARE\\QEMU", "QEMU" },

    { L"SOFTWARE\\Citrix\\XenTools", "Xen" }
};

//Проверяем есть ли ключи в реестре
std::string CheckRegKeys()
{
    HKEY hKey;

    for (const auto& vm : virtualMachineKeys)
    {
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, vm.key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);

            return vm.name;
        }
    }

    return "host";
}
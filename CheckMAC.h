#pragma once
#include <iostream>

#ifdef CHECKMAC_EXPORTS
#define CHECKMAC_API __declspec(dllexport) 
#else
#define CHECKMAC_API __declspec(dllimport)
#endif

extern "C" CHECKMAC_API std::string getVMonMAC();
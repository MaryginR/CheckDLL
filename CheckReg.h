#pragma once
#include <iostream>

#ifdef CHECKREG_EXPORTS
#define CHECKREG_API __declspec(dllexport)
#else
#define CHECKREG_API __declspec(dllimport) 
#endif

extern "C" CHECKREG_API std::string CheckRegKeys();
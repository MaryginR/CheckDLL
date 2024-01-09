#pragma once
#include <iostream>

#ifdef CHECKREMOTE_EXPORTS
#define CHECKREMOTE_API __declspec(dllexport)
#else
#define CHECKREMOTE_API __declspec(dllimport) 
#endif

extern "C" CHECKREMOTE_API std::string CheckRegKeys();
#pragma once
#include <iostream>

#ifdef CHECKRDP_EXPORTS
#define CHECKRDP_API __declspec(dllexport)
#else
#define CHECKRDP_API __declspec(dllimport) 
#endif

extern "C" CHECKRDP_API bool IsRDPConnection();
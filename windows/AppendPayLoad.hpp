// AppendPayLoad.hpp
//
// Changing a Signed Executable Without Altering Windows Digital Signature
// https://blog.barthe.ph/2009/02/22/change-signed-executable/
//
// Author:
//      Aymeric Barthe <aymeric@barthe.ph> - Original author (2009)

#ifndef __APPENDPAYLOAD_APPENDPAYLOAD__H__
#define __APPENDPAYLOAD_APPENDPAYLOAD__H__

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#include <tchar.h>

#endif // __APPENDPAYLOAD_APPENDPAYLOAD__H__
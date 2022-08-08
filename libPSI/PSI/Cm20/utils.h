#pragma once

#include "cryptoTools/Common/Defines.h"

namespace osuCrypto {

	extern u64 h1LengthInBytes;
    extern u64 bucket1;
    extern u64 bucket2;

	u64 getWidthMeetStatSecParam(u64 n1, u64 n2, u64 m, u64 statSecParam = 40, u64 cmpSecParam = 128);
}
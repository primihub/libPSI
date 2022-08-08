#pragma once

#include "cryptoTools/Common/Defines.h"

namespace osuCrypto {

	u64 getWidthMeetStatSecParam(u64 n1, u64 n2, u64 m, u64 statSecParam = 40, u64 cmpSecParam = 128);
}
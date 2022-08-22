#pragma once

#include "libPSI/config.h"
#ifdef ENABLE_KKRT_PSI

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/NChooseOne/NcoOtExt.h"
#include "libPSI/Tools/CuckooHasher.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

namespace osuCrypto
{

    class MKkrtPsiReceiver : public TimerAdapter
    {
    public:
        MKkrtPsiReceiver();
        ~MKkrtPsiReceiver();

        u64 mRecverSize,mSenderSize,mStatSecParam;
        std::vector<u64> mIntersection;
        CuckooIndex<ThreadSafe> mIndex;

        std::vector<KkrtNcoOtReceiver> mOtRecvs;

        block mHashingSeed;

        u64 stepSize = 1 << 10;

        std::vector<PRNG> prngs;
        
        void init(u64 senderSize, u64 recverSize, u64 statSecParam, span<Channel> chls, block seed);

        void sendInput(span<block> inputs, span<Channel> chls, span<Channel> mchls);
    };




}
#endif
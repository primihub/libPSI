#pragma once

#include "libPSI/config.h"
#ifdef ENABLE_KKRT_PSI

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Channel.h>
#include <libOTe/NChooseOne/NcoOtExt.h>
#include "cryptoTools/Crypto/PRNG.h"
#include <cryptoTools/Common/CuckooIndex.h>
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

namespace osuCrypto
{


	class MKkrtPsiSender : public TimerAdapter
	{
	public:
		MKkrtPsiSender();
		~MKkrtPsiSender();

		u64 mSenderSize, mRecverSize, mStatSecParam;
        PRNG mPrng;
		std::vector<PRNG> prngs;
        std::vector<u64> mPermute;

		//SimpleIndex mIndex;
        CuckooParam mParams;
		block mHashingSeed;

        u64 stepSize = 1 << 10;

        std::vector<KkrtNcoOtSender> mOtSenders;

		void init(u64 senderSize, u64 recverSize, u64 statSecParam, span<Channel> chls, block seed);

		void sendInput(span<block> inputs, span<Channel> chls, span<Channel> mchls);
	};

}
#endif
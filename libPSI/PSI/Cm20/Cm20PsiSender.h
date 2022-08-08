
#include "libPSI/config.h"

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "utils.h"

namespace osuCrypto
{

	class Cm20PsiSender : public TimerAdapter
	{
	public:
		Cm20PsiSender();
		~Cm20PsiSender();

		u64 mSenderSize, mReceiverSize, mStatSecParam;
		u64 height, width;

        u64 h1LengthInBytes = 32;
        u64 bucket1 = 1 << 8;
        u64 bucket2 = 1 << 8;

		block commonSeed;
		PRNG mPrng; 

		void init(u64 senderSize, u64 receiverSize, double scale, u64 statSecParam, span<Channel> chls, block seed);
		void init(u64 senderSize, u64 receiverSize, double scale, u64 statSecParam, Channel & chl0, block seed);

		void sendInput(span<block> inputs, Channel& chl);
		void sendInput(span<block> inputs, span<Channel> chls);

		void randomizeInputs(block* sendSet, span<block> &inputs);
		void recvAndComputeMatrixAndComputeHashKey(block *sendSet, std::vector<block> &otMessages, BitVector & choices, u8** transHashInputs, auto chl);
		void computeInputsHashAndSend(u8** transHashInputs, auto chl);
	};

}
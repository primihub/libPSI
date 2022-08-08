
#include "libPSI/config.h"
#include "utils.h"

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"


namespace osuCrypto
{

    class Cm20PsiReceiver : public TimerAdapter
    {
    public:
        Cm20PsiReceiver();
        ~Cm20PsiReceiver();

        u64 mReceiverSize,mSenderSize,mStatSecParam;
        u64 height, width;
        std::vector<u32> mIntersection;

        u64 h1LengthInBytes = 32;
        u64 bucket1 = 1 << 8;
        u64 bucket2 = 1 << 8;

        block commonSeed;
        PRNG mPrng;
        
        void init(u64 senderSize, u64 recverSize, double scale, u64 statSecParam, Channel chl0,  block seed);
        void init(u64 senderSize, u64 recverSize, double scale, u64 statSecParam, span<Channel> chls,  block seed);
        void sendInput(span<block> inputs, Channel& chl);
        void sendInput(span<block> inputs, span<Channel> chls);

        void randomizeInputs(block* recvSet, span<block> &inputs);
        void computeAndSendMatrixAndComputeHashKey(block* recvSet, std::vector<std::array<block, 2>> &otMessages, u8** transHashInputs, auto chl);
        void computeInputsHash(std::unordered_map<u64, std::vector<std::pair<block, u32>>> &allHashes, u8** transHashInputs);
        void receiveSenderHashAndComputePsi(std::unordered_map<u64, std::vector<std::pair<block, u32>>> &allHashes, auto chl);
    };




}
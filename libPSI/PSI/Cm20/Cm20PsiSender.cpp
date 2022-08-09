
#include "libPSI/config.h"
#include "Cm20PsiSender.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto
{

    Cm20PsiSender::Cm20PsiSender()
    {
    }

    Cm20PsiSender::~Cm20PsiSender()
    {
    }

    void Cm20PsiSender::init(u64 senderSize, u64 receiverSize, double scale, u64 statSec, Channel & chl0, block seed)
    {
        std::array<Channel, 1> c{ chl0 };
        init(senderSize, receiverSize, scale, statSec, c, seed);
    }

    void Cm20PsiSender::init(u64 senderSize, u64 receiverSize, double scale, u64 statSec, span<Channel> chls, block seed)
    {
        mStatSecParam = statSec;
        mSenderSize = senderSize;
        mReceiverSize = receiverSize;
        height = mReceiverSize * scale;
        width = getWidthMeetStatSecParam(mSenderSize, mReceiverSize, height);

        // we need a random hash function, so both commit to a seed and then decommit later
        mPrng.SetSeed(seed);
        block myHashSeeds;
        myHashSeeds = mPrng.get<block>();
        auto& chl = chls[0];
        chl.asyncSend((u8*)&myHashSeeds, sizeof(block));

        block theirHashingSeeds;
        auto fu = chl.asyncRecv((u8*)&theirHashingSeeds, sizeof(block));
        fu.get();
        commonSeed = myHashSeeds ^ theirHashingSeeds;

        setTimePoint("cm20.Recv.Init.end");
    }


    void Cm20PsiSender::sendInput(span<block> inputs, Channel & chl)
    {
        std::array<Channel, 1> chls{ chl };
        sendInput(inputs, chls);
    }

    void Cm20PsiSender::randomizeInputs(block* sendSet, span<block> &inputs) {
        AES commonAes;
        commonAes.setKey(commonSeed);
        RandomOracle H1(h1LengthInBytes);

        block* aesInput = new block[8];
		block* aesOutput = new block[8];
        u8* h1Output = new u8[h1LengthInBytes];
		for (auto low = 0; low < mSenderSize; low += 8) {
            auto up = low + 8 < mSenderSize ? low + 8 : mSenderSize;
            for (auto j = low; j < up; j++) {
                H1.Reset();
                H1.Update((u8*)(inputs.data() + j), sizeof(block));
                H1.Final(h1Output);
                aesInput[j-low] = *(block*)h1Output;
			    sendSet[j] = *(block*)(h1Output + sizeof(block));
            }
            if ((up - low) == 8) {
                commonAes.ecbEnc8Blocks(aesInput, aesOutput);
            } else {
                for (auto j = 0; j < (up-low); j++) {
                    commonAes.ecbEncBlock(aesInput[j], aesOutput[j]);
                }
            }
            for (auto j = low; j < up; j++) {
                sendSet[j] = _mm_xor_si128(sendSet[j], aesOutput[j-low]);
            }
		}

        delete[] aesInput;
        delete[] aesOutput;
        delete[] h1Output;
    }

    void Cm20PsiSender::recvAndComputeMatrixAndComputeHashKey(block *sendSet, std::vector<block> &otMessages, BitVector & choices, u8** transHashInputs, auto chl) {
        u64 heightInBytes = (height + 7) / 8;
        u64 logHeight = ceil(log2(height));
        u64 locationInBytes = (logHeight + 7) / 8;
        u64 widthBucket1 = sizeof(block) / locationInBytes;
        u64 shift = (1 << logHeight) - 1;

        AES commonAes;
        commonAes.setKey(commonSeed);

        block randomLocations[bucket1];
        u8* transLocations[widthBucket1];
        u8* matrixC[widthBucket1];
		for (auto i = 0; i < widthBucket1; ++i) {
			transLocations[i] = new u8[mReceiverSize * locationInBytes + sizeof(u32)];
			matrixC[i] = new u8[heightInBytes];
		}
        u8* recvMatrix = new u8[heightInBytes];

        for (auto wLeft = 0; wLeft < width; wLeft += widthBucket1) {
			auto wRight = wLeft + widthBucket1 < width ? wLeft + widthBucket1 : width;
			auto w = wRight - wLeft;
			//////////// Compute random locations (transposed) ////////////////
			for (auto low = 0; low < mSenderSize; low += bucket1) {
				auto up = low + bucket1 < mSenderSize ? low + bucket1 : mSenderSize;
				commonAes.ecbEncBlocks(sendSet + low, up - low, randomLocations); 
				for (auto i = 0; i < w; ++i) {
					for (auto j = low; j < up; ++j) {
						memcpy(transLocations[i] + j * locationInBytes, (u8*)(randomLocations + (j - low)) + i * locationInBytes, locationInBytes);
					}
				}
			}
			//////////////// Extend OTs and compute matrix C ///////////////////
			for (auto i = 0; i < w; ++i) {
				PRNG prng(otMessages[i + wLeft]);
				prng.get(matrixC[i], heightInBytes);
				chl.recv(recvMatrix, heightInBytes);
				if (choices[i + wLeft]) {
					for (auto j = 0; j < heightInBytes; ++j) {
						matrixC[i][j] ^= recvMatrix[j];
					}
				}
			}
			///////////////// Compute hash inputs (transposed) /////////////////////
			for (auto i = 0; i < w; ++i) {
				for (auto j = 0; j < mSenderSize; ++j) {
					auto location = ((*(u32*)(transLocations[i] + j * locationInBytes)) & shift) % height;
					transHashInputs[i + wLeft][j >> 3] |= (u8)((bool)(matrixC[i][location >> 3] & (1 << (location & 7)))) << (j & 7);
				}		
			}
		}

        delete[] recvMatrix;
        for (auto i = 0; i < widthBucket1; ++i) {
            delete[] transLocations[i];
            delete[] matrixC[i];
		}
    }

    void Cm20PsiSender::computeInputsHashAndSend(u8** transHashInputs, auto chl) {
        u64 hashLengthInBytes = (ceil(mStatSecParam+log2(mSenderSize)+log2(mReceiverSize))+7)/8;
        u64 widthInBytes = (width + 7) / 8;

        RandomOracle H(hashLengthInBytes);

        u8 hashOutput[sizeof(block)];
        u8* hashInputs[bucket2];
        for (auto i = 0; i < bucket2; ++i) {
			hashInputs[i] = new u8[widthInBytes];
		}
        u8* sentBuff = new u8[bucket2 * hashLengthInBytes];

        for (auto low = 0; low < mSenderSize; low += bucket2) {
			auto up = low + bucket2 < mSenderSize ? low + bucket2 : mSenderSize;
			for (auto j = low; j < up; ++j) {
				memset(hashInputs[j - low], 0, widthInBytes);
			}
			for (auto i = 0; i < width; ++i) {
				for (auto j = low; j < up; ++j) {
					hashInputs[j - low][i >> 3] |= (u8)((bool)(transHashInputs[i][j >> 3] & (1 << (j & 7)))) << (i & 7);
				}
			}
			for (auto j = low; j < up; ++j) {
				H.Reset();
				H.Update(hashInputs[j - low], widthInBytes);
				H.Final(hashOutput);
				memcpy(sentBuff + (j - low) * hashLengthInBytes, hashOutput, hashLengthInBytes);
			}
			
			chl.asyncSendCopy(sentBuff, (up - low) * hashLengthInBytes);
		}

        delete[] sentBuff;
        for (auto i = 0; i < bucket2; ++i) {
			delete[] hashInputs[i];
		}
    }

    void Cm20PsiSender::sendInput(span<block> inputs, span<Channel> chls)
    {
        auto chl = chls[0];

        IknpOtExtReceiver otExtReceiver;
		otExtReceiver.genBaseOts(mPrng, chl);
		BitVector choices(width);
		std::vector<block> otMessages(width);
		mPrng.get(choices.data(), choices.sizeBytes());
		otExtReceiver.receive(choices, otMessages, mPrng, chl);
        setTimePoint("cm20.Send.baseot.end");

        block* sendSet = new block[mSenderSize];
        randomizeInputs(sendSet, inputs);
        setTimePoint("cm20.Send.randomize.end");

        u64 senderSizeInBytes = (mSenderSize + 7) / 8;
        u8* transHashInputs[width];
		for (auto i = 0; i < width; ++i) {
			transHashInputs[i] = new u8[senderSizeInBytes];
			memset(transHashInputs[i], 0, senderSizeInBytes);
		}
        recvAndComputeMatrixAndComputeHashKey(sendSet, otMessages, choices, transHashInputs, chl);
        setTimePoint("cm20.Send.matrix.end");

        computeInputsHashAndSend(transHashInputs, chl);
        setTimePoint("cm20.Send.hash.end");

        delete[] sendSet;
        for (auto i = 0; i < width; ++i) {
			delete[] transHashInputs[i];
		}
    }
}


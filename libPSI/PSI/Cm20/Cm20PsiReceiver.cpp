
#include "libPSI/config.h"
#include "Cm20PsiReceiver.h"
#include <future>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include <libOTe/Base/BaseOT.h>
#include <unordered_map>
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include <iomanip>

namespace osuCrypto
{


    Cm20PsiReceiver::Cm20PsiReceiver()
    {
    }


    Cm20PsiReceiver::~Cm20PsiReceiver()
    {
    }

    void Cm20PsiReceiver::init(u64 senderSize, u64 recverSize, double scale, u64 statSecParam, Channel  chl0, block seed)
    {
        std::array<Channel, 1> chans{ chl0 };
        init(senderSize, recverSize, scale, 1, statSecParam, chans, seed);
    }


    void Cm20PsiReceiver::init(u64 senderSize, u64 recverSize, double scale, u64 nThread, u64 statSecParam, span<Channel> chls, block seed)
    {
        mStatSecParam = statSecParam;
        mSenderSize = senderSize;
        mReceiverSize = recverSize;
        numThreads = nThread;
        height = std::max(u64(256), u64(mReceiverSize * scale));
        width = getWidthMeetStatSecParam(mSenderSize, mReceiverSize, height);
        
        mPrng.SetSeed(seed);
        block myHashSeeds;
        myHashSeeds = mPrng.get<block>();
        auto& chl0 = chls[0];
        // we need a random hash function, so both commit to a seed and then decommit later
        chl0.asyncSend((u8*)&myHashSeeds, sizeof(block));
        block theirHashingSeeds;
        auto fu = chl0.asyncRecv((u8*)&theirHashingSeeds, sizeof(block));
        fu.get();
        commonSeed = myHashSeeds ^ theirHashingSeeds;

        setTimePoint("cm20.Recv.Init.end");
    }

    void Cm20PsiReceiver::sendInput(span<block> inputs, Channel & chl)
    {
        std::array<Channel, 1> chls{ chl };
        sendInput(inputs,  chls );
    }

    void Cm20PsiReceiver::randomizeInputs(block* recvSet, span<block> &inputs) {
        auto go = [&](u64 start, u64 end) {
            AES commonAes;
            commonAes.setKey(commonSeed);
            RandomOracle H1(h1LengthInBytes);

            block* aesInput = new block[8];
		    block* aesOutput = new block[8];
            u8* h1Output = new u8[h1LengthInBytes];
		    for (auto low = start; low < end; low += 8) {
                auto up = low + 8 < end ? low + 8 : end;
                for (auto j = low; j < up; j++) {
                    H1.Reset();
                    H1.Update((u8*)(inputs.data() + j), sizeof(block));
                    H1.Final(h1Output);
                    aesInput[j-low] = *(block*)h1Output;
		    	    recvSet[j] = *(block*)(h1Output + sizeof(block));
                }
                if ((up - low) == 8) {
                    commonAes.ecbEnc8Blocks(aesInput, aesOutput);
                } else {
                    for (auto j = 0; j < (up-low); j++) {
                        commonAes.ecbEncBlock(aesInput[j], aesOutput[j]);
                    }
                }
                for (auto j = low; j < up; j++) {
                    recvSet[j] = _mm_xor_si128(recvSet[j], aesOutput[j-low]);
                }
		    }
            delete[] aesInput;
            delete[] aesOutput;
            delete[] h1Output;
		};
        std::thread threads[numThreads];
        u64 thrdSize = std::ceil(1.0 * mReceiverSize / numThreads);
        for (u64 i = 0; i < numThreads; i++) {
            u64 start = i * thrdSize;
            u64 end = start + thrdSize;
            threads[i] = std::thread(go, start, std::min(mReceiverSize, end));
        }
        for (u64 i = 0; i < numThreads; i++) {
            threads[i].join();
        }
    }

    void Cm20PsiReceiver::computeAndSendMatrixAndComputeHashKey(block* recvSet, std::vector<std::array<block, 2>> &otMessages, u8** transHashInputs, span<Channel> chls) {
        u64 heightInBytes = (height + 7) / 8;
        u64 logHeight = ceil(log2(height));
        u64 locationInBytes = (logHeight + 7) / 8;
        u64 widthBucket1 = sizeof(block) / locationInBytes;
        u64 shift = (1 << logHeight) - 1;

        auto go = [&](u64 pid, u64 start, u64 end) {
            AES commonAes;
            commonAes.setKey(commonSeed);

            block randomLocations[bucket1];
            u8* matrixA[widthBucket1];
            u8* matrixDelta[widthBucket1];
            u8* transLocations[widthBucket1];
            u8* sentMatrix[widthBucket1];
            for (auto i = 0; i < widthBucket1; ++i) {
                matrixA[i] = new u8[heightInBytes];
                matrixDelta[i] = new u8[heightInBytes];
                transLocations[i] = new u8[mReceiverSize * locationInBytes + sizeof(u32)];
                sentMatrix[i] = new u8[heightInBytes];
            }

            for (auto wLeft = start; wLeft < end; wLeft += widthBucket1) {
                auto wRight = wLeft + widthBucket1 < end ? wLeft + widthBucket1 : end;
                auto w = wRight - wLeft;
                //////////// Compute random locations (transposed) ////////////////
                for (auto low = 0; low < mReceiverSize; low += bucket1) {
                    auto up = low + bucket1 < mReceiverSize ? low + bucket1 : mReceiverSize;
                    commonAes.ecbEncBlocks(recvSet + low, up - low, randomLocations); 
                    for (auto i = 0; i < w; ++i) {
                        for (auto j = low; j < up; ++j) {
                            memcpy(transLocations[i] + j * locationInBytes, (u8*)(randomLocations + (j - low)) + i * locationInBytes, locationInBytes);
                        }
                    }
                }
                //////////// Compute matrix Delta /////////////////////////////////
                for (auto i = 0; i < widthBucket1; ++i) {
                    memset(matrixDelta[i], 255, heightInBytes);
                }
                for (auto i = 0; i < w; ++i) {
                    for (auto j = 0; j < mReceiverSize; ++j) {
                        auto location = ((*(u32*)(transLocations[i] + j * locationInBytes)) & shift) % height;
                        matrixDelta[i][location >> 3] &= ~(1 << (location & 7));
                    }
                }
                //////////////// Compute matrix A & sent matrix ///////////////////////
                for (auto i = 0; i < w; ++i) {
                    PRNG prng(otMessages[i + wLeft][0]);
                    prng.get(matrixA[i], heightInBytes);
                    prng.SetSeed(otMessages[i + wLeft][1]);
                    prng.get(sentMatrix[i], heightInBytes);
                    for (auto j = 0; j < heightInBytes; ++j) {
                        sentMatrix[i][j] ^= matrixA[i][j] ^ matrixDelta[i][j];
                    }
                    chls[pid].asyncSendCopy(sentMatrix[i], heightInBytes);
                }
                ///////////////// Compute hash inputs (transposed) /////////////////////
                for (auto i = 0; i < w; ++i) {
                    for (auto j = 0; j < mReceiverSize; ++j) {
                        auto location = ((*(u32*)(transLocations[i] + j * locationInBytes)) & shift) % height;
                        transHashInputs[i + wLeft][j >> 3] |= (u8)((bool)(matrixA[i][location >> 3] & (1 << (location & 7)))) << (j & 7);
                    }		
                }
            }
            for (auto i = 0; i < widthBucket1; ++i) {
                delete[] transLocations[i];
                delete[] matrixA[i];
                delete[] matrixDelta[i];
                delete[] sentMatrix[i];
            }
        };
        std::thread threads[numThreads];
        u64 thrdSize = std::ceil(1.0 * width / numThreads);
        for (u64 i = 0; i < numThreads; i++) {
            u64 start = i * thrdSize;
            u64 end = start + thrdSize;
            threads[i] = std::thread(go, i, start, std::min(width, end));
        }
        for (u64 i = 0; i < numThreads; i++) {
            threads[i].join();
        }
    }

    void Cm20PsiReceiver::computeInputsHash(std::vector<std::unordered_map<u64, std::vector<std::pair<block, u32>>>> &allHashes, u8** transHashInputs) {
        /////////////////// Compute hash outputs ///////////////////////////
        u64 hashLengthInBytes = (ceil(mStatSecParam+log2(mSenderSize)+log2(mReceiverSize))+7)/8;
        u64 widthInBytes = (width + 7) / 8;

        auto go = [&](u64 pid, u64 start, u64 end) {
            RandomOracle H(hashLengthInBytes);

            u8* hashInputs[bucket2];
            for (auto i = 0; i < bucket2; ++i) {
		    	hashInputs[i] = new u8[widthInBytes];
		    }
            u8 hashOutput[sizeof(block)];
            memset(hashOutput, 0, sizeof(block));
            for (auto low = start; low < end; low += bucket2) {
		    	auto up = low + bucket2 < end ? low + bucket2 : end;
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
		    		allHashes[pid][*(u64*)hashOutput].push_back(std::make_pair(*(block*)hashOutput, j));
		    	}
		    }

            for (auto i = 0; i < bucket2; ++i) {
		    	delete[] hashInputs[i];
		    }
        };
        std::thread threads[numThreads];
        u64 thrdSize = std::ceil(1.0 * mReceiverSize / numThreads);
        for (u64 i = 0; i < numThreads; i++) {
            u64 start = i * thrdSize;
            u64 end = start + thrdSize;
            threads[i] = std::thread(go, i, start, std::min(mReceiverSize, end));
        }
        for (u64 i = 0; i < numThreads; i++) {
            threads[i].join();
        }
    }

    void Cm20PsiReceiver::receiveSenderHashAndComputePsi(std::vector<std::unordered_map<u64, std::vector<std::pair<block, u32>>>> &allHashes, span<Channel> chls) {
        u64 hashLengthInBytes = (ceil(mStatSecParam+log2(mSenderSize)+log2(mReceiverSize))+7)/8;

        std::vector<std::vector<u32>> threadIntersections(numThreads);
        auto go = [&](u64 pid, u64 start, u64 end) {
            u8* recvBuff = new u8[bucket2 * hashLengthInBytes];
            u8 hashOutput[sizeof(block)];
            memset(hashOutput, 0, sizeof(block));

            for (auto low = start; low < end; low += bucket2) {
                auto up = low + bucket2 < end ? low + bucket2 : end;
                chls[pid].recv(recvBuff, (up - low) * hashLengthInBytes);
                for (auto idx = 0; idx < up - low; ++idx) {
                    memcpy(hashOutput, recvBuff + idx * hashLengthInBytes, hashLengthInBytes);
                    u64 mapIdx = *(u64*)(hashOutput);
                    
                    for (u64 hashIndex = 0; hashIndex < numThreads; hashIndex++) {
                        auto found = allHashes[hashIndex].find(mapIdx);
                        if (found == allHashes[hashIndex].end()) continue;
                        bool intersection = false;
                        for (auto i = 0; i < found->second.size(); ++i) {
                            if (memcmp(&(found->second[i].first), recvBuff + idx * hashLengthInBytes, hashLengthInBytes) == 0) {
                                threadIntersections[pid].emplace_back(found->second[i].second);
                                intersection = true;
                                break;
                            }
                        }
                        if (intersection) break;
                    }
                }
            }

            delete[] recvBuff;
        };
        std::thread threads[numThreads];
        u64 thrdSize = std::ceil(1.0 * mSenderSize / numThreads);
        for (u64 i = 0; i < numThreads; i++) {
            u64 start = i * thrdSize;
            u64 end = start + thrdSize;
            threads[i] = std::thread(go, i, start, std::min(mSenderSize, end));
        }
        for (u64 i = 0; i < numThreads; i++) {
            threads[i].join();
            mIntersection.insert(mIntersection.end(), threadIntersections[i].begin(), threadIntersections[i].end());
        }
    }

    void Cm20PsiReceiver::sendInput(span<block> inputs, span<Channel> chls)
    {
        if (chls.size() != numThreads) {
            numThreads = chls.size();
        }

        IknpOtExtSender otExtSender;
        otExtSender.genBaseOts(mPrng, chls[0]);
        std::vector<std::array<block, 2>> otMessages(width);
        otExtSender.send(otMessages, mPrng, chls[0]);
        setTimePoint("cm20.Recv.baseot.end");

        block* recvSet = new block[mReceiverSize];
        randomizeInputs(recvSet, inputs);
        setTimePoint("cm20.Recv.randomize.end");

        u64 receiverSizeInBytes = (mReceiverSize + 7) / 8;
        u8* transHashInputs[width];
		for (auto i = 0; i < width; ++i) {
			transHashInputs[i] = new u8[receiverSizeInBytes];
			memset(transHashInputs[i], 0, receiverSizeInBytes);
		}
        computeAndSendMatrixAndComputeHashKey(recvSet, otMessages, transHashInputs, chls);
        setTimePoint("cm20.Recv.matrix.end");

        std::vector<std::unordered_map<u64, std::vector<std::pair<block, u32>>>> allHashes(numThreads);
        computeInputsHash(allHashes, transHashInputs);
        setTimePoint("cm20.Recv.hash.end");

        receiveSenderHashAndComputePsi(allHashes, chls);
        setTimePoint("cm20.Recv.psi.end");

        delete[] recvSet;
        for (auto i = 0; i < width; ++i) {
			delete[] transHashInputs[i];
		}
    }
}
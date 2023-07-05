
#include "libPSI/config.h"
#ifdef ENABLE_KKRT_PSI
#include "MKkrtPsiReceiver.h"
#include <future>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libPSI/Tools/SimpleHasher.h"
#include "libOTe/Base/BaseOT.h"
#include <unordered_map>
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "libOTe/Tools/Tools.h"
#include <iomanip>
namespace osuCrypto
{


    MKkrtPsiReceiver::MKkrtPsiReceiver()
    {
    }


    MKkrtPsiReceiver::~MKkrtPsiReceiver()
    {
    }

    void MKkrtPsiReceiver::init(u64 senderSize, u64 recverSize, u64 statSecParam, span<Channel> chls, block seed)
    {

        mStatSecParam = statSecParam;
        mSenderSize = senderSize;
        mRecverSize = recverSize;

        CuckooParam param = CuckooParam{ 0, 1.27, 3, std::max<u64>(200, recverSize) };
        mIndex.init(param);

        setTimePoint("kkrt.Recv.Init.start");
        PRNG prng(seed);
        block myHashSeeds;
        myHashSeeds = prng.get<block>();
        auto& chl0 = chls[0];

        chl0.asyncSend((u8*)&myHashSeeds, sizeof(block));
        block theirHashingSeeds;
        chl0.recv((u8*)&theirHashingSeeds, sizeof(block));

        mHashingSeed = myHashSeeds ^ theirHashingSeeds;

        mOtRecvs.resize(chls.size());
        prngs.resize(chls.size());
        std::thread otThrd[chls.size()];
        for (u64 i = 0; i < chls.size(); i++) {
            prngs[i] = PRNG(prng.get<block>());
            otThrd[i] = std::thread([i, this, &chls]() {
                mOtRecvs[i].configure(false, 40, 128);

                DefaultBaseOT baseBase;
                std::array<block, 128> baseBaseOT;
                BitVector baseBaseChoice(128);
                baseBaseChoice.randomize(prngs[i]);
                baseBase.receive(baseBaseChoice, baseBaseOT, prngs[i], chls[i]);

                IknpOtExtSender base;
                base.setBaseOts(baseBaseOT, baseBaseChoice, chls[i]);
                std::vector<std::array<block, 2>> baseOT(mOtRecvs[i].getBaseOTCount());
                base.send(baseOT, prngs[i], chls[i]);

                mOtRecvs[i].setBaseOts(baseOT, prngs[i], chls[i]);
                std::array<block, 4> keys;
                PRNG(mHashingSeed).get(keys.data(), keys.size());
                mOtRecvs[i].mMultiKeyAES.setKeys(keys);
            });
        }

        for (u64 i = 0; i < chls.size(); i++) {
            otThrd[i].join();
        }
    }

    void init_ot(u64 numOtExt, PRNG& prng, Channel& chl, KkrtNcoOtReceiver &otReceiver) {
        if (otReceiver.hasBaseOts() == false)
            otReceiver.genBaseOts(prng, chl);


        static const u64 superBlkSize(8);

        // this will be used as temporary buffers of 128 columns,
        // each containing 1024 bits. Once transposed, they will be copied
        // into the T1, T0 buffers for long term storage.
        std::array<std::array<block, superBlkSize>, 128> t0;
        std::array<std::array<block, superBlkSize>, 128> t1;

        // we are going to process OTs in blocks of 128 * superblkSize messages.
        u64 numSuperBlocks = ((numOtExt + 127) / 128 + superBlkSize - 1) / superBlkSize;
        u64 numCols = otReceiver.mGens.size();

        // We need two matrices, T0 and T1. These will hold the expanded and transposed
        // rows that we got the using the base OTs as PRNG seed.
        otReceiver.mT0.resize(numOtExt, numCols / 128);
        otReceiver.mT1.resize(numOtExt, numCols / 128);

        // The is the index of the last correction value u = T0 ^ T1 ^ c(w)
        // that was sent to the sender.
        otReceiver.mCorrectionIdx = 0;

        // the index of the OT that has been completed.
        u64 doneIdx = 0;

        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. We do 128 columns
        //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for
        //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector
        //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a time.
        //   So that's what we do.
        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // compute at what row does the user want us to stop.
            // The code will still compute the transpose for these
            // extra rows, but it is thrown away.
            u64 stopIdx
                = doneIdx
                + std::min<u64>(u64(128) * superBlkSize, numOtExt - doneIdx);


            for (u64 i = 0; i < numCols / 128; ++i)
            {

                for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
                {
                    // generate the column indexed by colIdx. This is done with
                    // AES in counter mode acting as a PRNG. We don't use the normal
                    // PRNG interface because that would result in a data copy when
                    // we move it into the T0,T1 matrices. Instead we do it directly.
                    otReceiver.mGens[colIdx][0].ecbEncCounterMode(otReceiver.mGensBlkIdx[colIdx], superBlkSize, ((block*)t0.data() + superBlkSize * tIdx));
                    otReceiver.mGens[colIdx][1].ecbEncCounterMode(otReceiver.mGensBlkIdx[colIdx], superBlkSize, ((block*)t1.data() + superBlkSize * tIdx));

                    // increment the counter mode idx.
                    otReceiver.mGensBlkIdx[colIdx] += superBlkSize;
                }

                // transpose our 128 columns of 1024 bits. We will have 1024 rows,
                // each 128 bits wide.
                transpose128x1024(t0);
                transpose128x1024(t1);

                // This is the index of where we will store the matrix long term.
                // doneIdx is the starting row. i is the offset into the blocks of 128 bits.
                // __restrict isn't crucial, it just tells the compiler that this pointer
                // is unique and it shouldn't worry about pointer aliasing.
                block* __restrict mT0Iter = otReceiver.mT0.data() + otReceiver.mT0.stride() * doneIdx + i;
                block* __restrict mT1Iter = otReceiver.mT1.data() + otReceiver.mT1.stride() * doneIdx + i;

                for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
                {
                    // because we transposed 1024 rows, the indexing gets a bit weird. But this
                    // is the location of the next row that we want. Keep in mind that we had long
                    // **contiguous** columns.
                    block* __restrict t0Iter = ((block*)t0.data()) + j;
                    block* __restrict t1Iter = ((block*)t1.data()) + j;

                    // do the copy!
                    for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                    {
                        *mT0Iter = *(t0Iter);
                        *mT1Iter = *(t1Iter);

                        t0Iter += superBlkSize;
                        t1Iter += superBlkSize;

                        mT0Iter += otReceiver.mT0.stride();
                        mT1Iter += otReceiver.mT0.stride();
                    }
                }
            }

            doneIdx = stopIdx;
        }

    }

    void cuckooHash(span<block> inputs, span<Channel> chls, block mHashingSeed, CuckooIndex<ThreadSafe> &mIndex) {
        std::thread hashThrd[chls.size()];
        std::vector<block> prehash(inputs.size());
        u64 thrdHashSize = std::ceil(1.0 * inputs.size() / chls.size());
        for (u64 pid = 0; pid < chls.size(); pid++) {
            auto hashStart = pid * thrdHashSize;
            auto hashEnd = std::min(inputs.size(), hashStart + thrdHashSize);
            hashThrd[pid] = std::thread([&prehash, hashStart, hashEnd, &inputs, mHashingSeed]() {
                AES hasher(mHashingSeed);
                hasher.ecbEncBlocks(inputs.data() + hashStart, hashEnd - hashStart, prehash.data() + hashStart);
                auto iter1 = inputs.data() + hashStart;
                auto iter2 = prehash.data() + hashStart;
                while (iter1 != inputs.data() + hashEnd) {
                    *iter2 = *iter2 ^ *iter1;
                    iter2++;
                    iter1++;
                }
            });
        }
        for (u64 pid = 0; pid < chls.size(); pid++) {
            hashThrd[pid].join();
        }
        mIndex.insert(prehash);
    }

    void MKkrtPsiReceiver::sendInput(span<block> inputs, span<Channel> chls, span<Channel> mchls)
    {
        // check that the number of inputs is as expected.
        if (inputs.size() != mRecverSize)
            throw std::runtime_error("inputs.size() != mN");
        setTimePoint("kkrt.R Online.Start");

        u64 maskByteSize = static_cast<u64>(mStatSecParam + std::log2(mSenderSize * mRecverSize) + 7) / 8;//by byte

        cuckooHash(inputs, chls, mHashingSeed, mIndex);

        std::array<std::unordered_map<u64, std::pair<block, u64>>, 3> localMasks;
        localMasks[0].reserve(mIndex.mBins.size()); //upper bound of # mask
        localMasks[1].reserve(mIndex.mBins.size());
        localMasks[2].reserve(mIndex.mBins.size());
        std::vector<std::mutex> mtx_syn(3);

        //======================Bucket BINs (not stash)==========================
        setTimePoint("kkrt.R Online.computeBucketMask start");
        std::thread oprfThrd[chls.size()];
        u64 thrdBinSize = std::ceil(1.0 * mIndex.mBins.size() / chls.size());
        for (u64 pid = 0; pid < chls.size(); pid++) {
            auto binStart = pid * thrdBinSize;
            auto binEnd = std::min(mIndex.mBins.size(), binStart + thrdBinSize);
            oprfThrd[pid] = std::thread([pid, binStart, maskByteSize, binEnd, &chls, &mtx_syn, this, &localMasks, &inputs]() {
                for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
                {
                    auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
                    auto stepEnd = stepIdx + currentStepSize;
                    init_ot(currentStepSize, prngs[pid], chls[pid], mOtRecvs[pid]);
                    for (u64 bIdx = stepIdx; bIdx < stepEnd; bIdx++)
                    {
                        auto& bin = mIndex.mBins[bIdx];
                        if (bin.isEmpty() == false)
                        {
                            auto idx = bin.idx();
                            auto hIdx = CuckooIndex<>::minCollidingHashIdx(bIdx,mIndex.mHashes[idx], 3, mIndex.mBins.size());
                            auto& item = inputs[idx];
                            block encoding = ZeroBlock;
                            mOtRecvs[pid].encode(bIdx - stepIdx, &item, &encoding, maskByteSize);
                            mtx_syn[hIdx].lock();
                            localMasks[hIdx].emplace(encoding.as<u64>()[0], std::pair<block, u64>(encoding, idx));
                            mtx_syn[hIdx].unlock();
                        }
                        else
                        {
                            mOtRecvs[pid].zeroEncode(bIdx - stepIdx);
                        }
                    }
                    chls[pid].asyncSendCopy((u8*)(mOtRecvs[pid].mT1.data() + (mOtRecvs[pid].mCorrectionIdx * mOtRecvs[pid].mT1.stride())), mOtRecvs[pid].mT1.stride() * currentStepSize * sizeof(block));
                    mOtRecvs[pid].mCorrectionIdx += currentStepSize;
                }
            });
        }

        for (u64 pid = 0; pid < chls.size(); pid++) {
            oprfThrd[pid].join();
        }

        setTimePoint("kkrt.R Online.sendBucketMask done");

        std::thread maskThrd[chls.size()];
        std::vector<std::vector<u64>> thrdIntersections(chls.size());
        for (u64 pid = 0; pid < chls.size(); pid++) {
            maskThrd[pid] = std::thread([pid, &mchls, &thrdIntersections, maskByteSize, &localMasks, this]() {
                Matrix<u8> myMaskBuff(1, stepSize * maskByteSize + 1);
                auto idxSize = std::min<u64>(maskByteSize, sizeof(u64));
                Matrix<u8> zeroMask(1, maskByteSize);
                memset(zeroMask.data(), 0, maskByteSize);

                u64 endFlag = 0;
                while (endFlag < localMasks.size()) {
                    mchls[pid].recv(myMaskBuff.data(), stepSize * maskByteSize + 1);
                    auto data = myMaskBuff.data();
                    u64 idxs;
                    u64 stepIndex;
                    u8 inputHash = myMaskBuff(0, stepSize * maskByteSize);
                    for (stepIndex = 0; stepIndex < stepSize; stepIndex++) {
                        if (memcmp(zeroMask.data(), data, maskByteSize) == 0) break;
                        memcpy(&idxs, data, idxSize);
                        auto iter = localMasks[inputHash].find(idxs);
                        if (iter != localMasks[inputHash].end() && memcmp(&iter->second.first, data, maskByteSize) == 0) {
                            thrdIntersections[pid].emplace_back(iter->second.second);
                        }
                        data += maskByteSize;
                    }
                    if (stepIndex != stepSize) endFlag++;
                }
            });
        }

        for (u64 pid = 0; pid < chls.size(); pid++) {
            maskThrd[pid].join();
            mIntersection.insert(mIntersection.end(), thrdIntersections[pid].begin(), thrdIntersections[pid].end());
        }

        setTimePoint("kkrt.R Online.Bucket done");


    }

}
#endif



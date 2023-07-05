
#include "libPSI/config.h"
#ifdef ENABLE_KKRT_PSI
#include "MKkrtPsiSender.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/CuckooIndex.h"
//#include <unordered_map>
#include "libPSI/Tools/SimpleIndex.h"
#include "libOTe/Tools/Tools.h"
#include <condition_variable>
#include <mutex>


namespace osuCrypto
{

    MKkrtPsiSender::MKkrtPsiSender()
    {
    }

    MKkrtPsiSender::~MKkrtPsiSender()
    {
    }
    //extern std::string hexString(u8* data, u64 length);

    void MKkrtPsiSender::init(u64 senderSize, u64 recverSize, u64 statSec, span<Channel> chls, block seed)
    {
        mStatSecParam = statSec;
        mSenderSize = senderSize;
        mRecverSize = recverSize;

        mPrng.SetSeed(seed);
        block myHashSeeds;
        myHashSeeds = mPrng.get<block>();
        auto& chl = chls[0];
        chl.asyncSend((u8*)&myHashSeeds, sizeof(block));

        block theirHashingSeeds;
        chl.recv((u8*)&theirHashingSeeds, sizeof(block));
        mHashingSeed = myHashSeeds ^ theirHashingSeeds;

        mParams = CuckooParam{ 0, 1.27, 3, std::max<u64>(200, recverSize) };
        if (mParams.mNumHashes != 3) throw std::runtime_error(LOCATION);

        mOtSenders.resize(chls.size());
        prngs.resize(chls.size());
        std::thread otThrd[chls.size()];
        for (u64 i = 0; i < chls.size(); i++) {
            prngs[i] = PRNG(mPrng.get<block>());
            otThrd[i] = std::thread([i, this, &chls]() {
                mOtSenders[i].configure(false, 40, 128);

                DefaultBaseOT baseBase;
                std::array<std::array<block, 2>, 128> baseBaseOT;
                baseBase.send(baseBaseOT, prngs[i], chls[i]);

                IknpOtExtReceiver base;
                base.setBaseOts(baseBaseOT, prngs[i], chls[i]);

                BitVector baseChoice(mOtSenders[i].getBaseOTCount());
                baseChoice.randomize(prngs[i]);
                std::vector<block> baseOT(mOtSenders[i].getBaseOTCount());
                base.receive(baseChoice, baseOT, prngs[i], chls[i]);

                mOtSenders[i].setBaseOts(baseOT, baseChoice, chls[i]);
                std::array<block, 4> keys;
                PRNG(mHashingSeed).get(keys.data(), keys.size());
                mOtSenders[i].mMultiKeyAES.setKeys(keys);
            });
        }

        setTimePoint("kkrt.S offline.perm start");

        for (u64 i = 0; i < chls.size(); i++) {
            otThrd[i].join();
        }
    }

    void init_ot(u64 numOTExt, PRNG& prng, Channel& chl, KkrtNcoOtSender &otSender) {
        if (otSender.hasBaseOts() == false)
            otSender.genBaseOts(prng, chl);


        static const u8 superBlkSize(8);


        // round up
        numOTExt = ((numOTExt + 127) / 128) * 128;

        // We need two matrices, one for the senders matrix T^i_{b_i} and
        // one to hold the the correction values. This is sometimes called
        // the u = T0 + T1 + C matrix in the papers.
        otSender.mT.resize(numOTExt, otSender.mGens.size() / 128);
        //char c;
        //chl.recv(&c, 1);

        otSender.mCorrectionVals.resize(numOTExt, otSender.mGens.size() / 128);

        // The receiver will send us correction values, this is the index of
        // the next one they will send.
        otSender.mCorrectionIdx = 0;

        // we are going to process OTs in blocks of 128 * superblkSize messages.
        u64 numSuperBlocks = (numOTExt / 128 + superBlkSize - 1) / superBlkSize;

        // the index of the last OT that we have completed.
        u64 doneIdx = 0;

        // a temp that will be used to transpose the sender's matrix
        std::array<std::array<block, superBlkSize>, 128> t;

        u64 numCols = otSender.mGens.size();

        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // compute at what row does the user want use to stop.
            // the code will still compute the transpose for these
            // extra rows, but it is thrown away.
            u64 stopIdx
                = doneIdx
                + std::min<u64>(u64(128) * superBlkSize, otSender.mT.bounds()[0] - doneIdx);

            // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
            for (u64 i = 0; i < numCols / 128; ++i)
            {
                // generate the columns using AES-NI in counter mode.
                for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
                {
                    otSender.mGens[colIdx].ecbEncCounterMode(otSender.mGensBlkIdx[colIdx], superBlkSize, ((block*)t.data() + superBlkSize * tIdx));
                    otSender.mGensBlkIdx[colIdx] += superBlkSize;
                }

                // transpose our 128 columns of 1024 bits. We will have 1024 rows,
                // each 128 bits wide.
                transpose128x1024(t);

                // This is the index of where we will store the matrix long term.
                // doneIdx is the starting row. i is the offset into the blocks of 128 bits.
                // __restrict isn't crucial, it just tells the compiler that this pointer
                // is unique and it shouldn't worry about pointer aliasing.
                block* __restrict mTIter = otSender.mT.data() + doneIdx * otSender.mT.stride() + i;

                for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
                {
                    // because we transposed 1024 rows, the indexing gets a bit weird. But this
                    // is the location of the next row that we want. Keep in mind that we had long
                    // **contiguous** columns.
                    block* __restrict tIter = (((block*)t.data()) + j);

                    // do the copy!
                    for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                    {
                        *mTIter = *tIter;

                        tIter += superBlkSize;
                        mTIter += otSender.mT.stride();
                    }
                }

            }

            doneIdx = stopIdx;
        }
    }


    void hashItems2(
        span<block> items,
        MatrixView<u64> mItemToBinMap,
        block hashingSeed,
        u64 numBins,
        PRNG& prng,
        MatrixView<u8> masks,
        span<u64> perm,
        u64 stepStart,
        u64 stepEnd
        )
    {

        std::array<block, 8> hashs;
        AES hasher(hashingSeed);

        auto mNumHashFunctions = mItemToBinMap.stride();
        auto mainSteps = (stepEnd - stepStart) / hashs.size();
        auto remSteps = (stepEnd - stepStart) % hashs.size();
        u64 itemIdx = stepStart;

        for (u64 i = 0; i < mainSteps; ++i, itemIdx += 8)
        {
            hasher.ecbEncBlocks(items.data() + itemIdx, 8, hashs.data());

            auto itemIdx0 = itemIdx + 0;
            auto itemIdx1 = itemIdx + 1;
            auto itemIdx2 = itemIdx + 2;
            auto itemIdx3 = itemIdx + 3;
            auto itemIdx4 = itemIdx + 4;
            auto itemIdx5 = itemIdx + 5;
            auto itemIdx6 = itemIdx + 6;
            auto itemIdx7 = itemIdx + 7;

            // compute the hash as  H(x) = AES(x) + x
            hashs[0] = hashs[0] ^ items[itemIdx0];
            hashs[1] = hashs[1] ^ items[itemIdx1];
            hashs[2] = hashs[2] ^ items[itemIdx2];
            hashs[3] = hashs[3] ^ items[itemIdx3];
            hashs[4] = hashs[4] ^ items[itemIdx4];
            hashs[5] = hashs[5] ^ items[itemIdx5];
            hashs[6] = hashs[6] ^ items[itemIdx6];
            hashs[7] = hashs[7] ^ items[itemIdx7];

            // Get the first bin that each of the items maps to
            auto bIdx00 = CuckooIndex<>::getHash(hashs[0], 0, numBins);
            auto bIdx10 = CuckooIndex<>::getHash(hashs[1], 0, numBins);
            auto bIdx20 = CuckooIndex<>::getHash(hashs[2], 0, numBins);
            auto bIdx30 = CuckooIndex<>::getHash(hashs[3], 0, numBins);
            auto bIdx40 = CuckooIndex<>::getHash(hashs[4], 0, numBins);
            auto bIdx50 = CuckooIndex<>::getHash(hashs[5], 0, numBins);
            auto bIdx60 = CuckooIndex<>::getHash(hashs[6], 0, numBins);
            auto bIdx70 = CuckooIndex<>::getHash(hashs[7], 0, numBins);

            // update the map with these bin indexes
            mItemToBinMap(itemIdx0, 0) = bIdx00;
            mItemToBinMap(itemIdx1, 0) = bIdx10;
            mItemToBinMap(itemIdx2, 0) = bIdx20;
            mItemToBinMap(itemIdx3, 0) = bIdx30;
            mItemToBinMap(itemIdx4, 0) = bIdx40;
            mItemToBinMap(itemIdx5, 0) = bIdx50;
            mItemToBinMap(itemIdx6, 0) = bIdx60;
            mItemToBinMap(itemIdx7, 0) = bIdx70;

            // get the second bin index
            auto bIdx01 = CuckooIndex<>::getHash(hashs[0], 1, numBins);
            auto bIdx11 = CuckooIndex<>::getHash(hashs[1], 1, numBins);
            auto bIdx21 = CuckooIndex<>::getHash(hashs[2], 1, numBins);
            auto bIdx31 = CuckooIndex<>::getHash(hashs[3], 1, numBins);
            auto bIdx41 = CuckooIndex<>::getHash(hashs[4], 1, numBins);
            auto bIdx51 = CuckooIndex<>::getHash(hashs[5], 1, numBins);
            auto bIdx61 = CuckooIndex<>::getHash(hashs[6], 1, numBins);
            auto bIdx71 = CuckooIndex<>::getHash(hashs[7], 1, numBins);

            // check if we get a collision with the first bin index
            u8 c01 = 1 & (bIdx00 == bIdx01);
            u8 c11 = 1 & (bIdx10 == bIdx11);
            u8 c21 = 1 & (bIdx20 == bIdx21);
            u8 c31 = 1 & (bIdx30 == bIdx31);
            u8 c41 = 1 & (bIdx40 == bIdx41);
            u8 c51 = 1 & (bIdx50 == bIdx51);
            u8 c61 = 1 & (bIdx60 == bIdx61);
            u8 c71 = 1 & (bIdx70 == bIdx71);

            // If we didnt get a collision, set the new bin index and otherwise set it to -1
            mItemToBinMap(itemIdx0, 1) = bIdx01 | (c01 * u64(-1));
            mItemToBinMap(itemIdx1, 1) = bIdx11 | (c11 * u64(-1));
            mItemToBinMap(itemIdx2, 1) = bIdx21 | (c21 * u64(-1));
            mItemToBinMap(itemIdx3, 1) = bIdx31 | (c31 * u64(-1));
            mItemToBinMap(itemIdx4, 1) = bIdx41 | (c41 * u64(-1));
            mItemToBinMap(itemIdx5, 1) = bIdx51 | (c51 * u64(-1));
            mItemToBinMap(itemIdx6, 1) = bIdx61 | (c61 * u64(-1));
            mItemToBinMap(itemIdx7, 1) = bIdx71 | (c71 * u64(-1));


            // repeat the process with the last hash function
            auto bIdx02 = CuckooIndex<>::getHash(hashs[0], 2, numBins);
            auto bIdx12 = CuckooIndex<>::getHash(hashs[1], 2, numBins);
            auto bIdx22 = CuckooIndex<>::getHash(hashs[2], 2, numBins);
            auto bIdx32 = CuckooIndex<>::getHash(hashs[3], 2, numBins);
            auto bIdx42 = CuckooIndex<>::getHash(hashs[4], 2, numBins);
            auto bIdx52 = CuckooIndex<>::getHash(hashs[5], 2, numBins);
            auto bIdx62 = CuckooIndex<>::getHash(hashs[6], 2, numBins);
            auto bIdx72 = CuckooIndex<>::getHash(hashs[7], 2, numBins);


            u8 c02 = 1 & (bIdx00 == bIdx02 || bIdx01 == bIdx02);
            u8 c12 = 1 & (bIdx10 == bIdx12 || bIdx11 == bIdx12);
            u8 c22 = 1 & (bIdx20 == bIdx22 || bIdx21 == bIdx22);
            u8 c32 = 1 & (bIdx30 == bIdx32 || bIdx31 == bIdx32);
            u8 c42 = 1 & (bIdx40 == bIdx42 || bIdx41 == bIdx42);
            u8 c52 = 1 & (bIdx50 == bIdx52 || bIdx51 == bIdx52);
            u8 c62 = 1 & (bIdx60 == bIdx62 || bIdx61 == bIdx62);
            u8 c72 = 1 & (bIdx70 == bIdx72 || bIdx71 == bIdx72);


            mItemToBinMap(itemIdx0, 2) = bIdx02 | (c02 * u64(-1));
            mItemToBinMap(itemIdx1, 2) = bIdx12 | (c12 * u64(-1));
            mItemToBinMap(itemIdx2, 2) = bIdx22 | (c22 * u64(-1));
            mItemToBinMap(itemIdx3, 2) = bIdx32 | (c32 * u64(-1));
            mItemToBinMap(itemIdx4, 2) = bIdx42 | (c42 * u64(-1));
            mItemToBinMap(itemIdx5, 2) = bIdx52 | (c52 * u64(-1));
            mItemToBinMap(itemIdx6, 2) = bIdx62 | (c62 * u64(-1));
            mItemToBinMap(itemIdx7, 2) = bIdx72 | (c72 * u64(-1));
        }

        // in case the input does not divide evenly by 8, handle the last few items.
        hasher.ecbEncBlocks(items.data() + itemIdx, remSteps, hashs.data());
        for (u64 i = 0; i < remSteps; ++i, ++itemIdx)
        {
            hashs[i] = hashs[i] ^ items[itemIdx];

            std::vector<u64> bIdxs(mNumHashFunctions);
            for (u64 h = 0; h < mNumHashFunctions; ++h)
            {
                auto bIdx = CuckooIndex<>::getHash(hashs[i], (u8)h, numBins);
                bool collision = false;

                bIdxs[h] = bIdx;
                for (u64 hh = 0; hh < h; ++hh)
                    collision |= (bIdxs[hh] == bIdx);

                u8 c = ((u8)collision & 1);
                mItemToBinMap(itemIdx, h) = bIdx | c * u64(-1);
            }
        }
    }



    void hashBinItems(
        span<block> items,
        block hashingSeed,
        u64 numBins,
        PRNG& prng,
        Matrix<u8> myMaskBuff,
        span<u64> perm,
        u64 numHashes,
        span<std::atomic<u64>> binIndex,
        span<u64> binIdx,
        span<u8> binHash,
        u64 threadNum
    ) {
        Matrix<u64> binIdxs(items.size(), numHashes);
        std::thread hashThrd[threadNum];
        u64 thrdHashSize = std::ceil(1.0 * items.size() / threadNum);
        for (u64 pid = 0; pid < threadNum; pid++) {
            auto hashStart = pid * thrdHashSize;
            auto hashEnd = std::min(items.size(), hashStart + thrdHashSize);
            hashThrd[pid] = std::thread([&items, &binIdxs, hashingSeed, numBins, &prng, &myMaskBuff, &perm, hashStart, hashEnd]() {
                hashItems2(items, binIdxs, hashingSeed, numBins, prng, myMaskBuff, perm, hashStart, hashEnd);
            });
        }
        for (u64 pid = 0; pid < threadNum; pid++) {
            hashThrd[pid].join();
        }

        std::mutex mtx_syn;
        for (u64 pid = 0; pid < threadNum; pid++) {
            auto hashStart = pid * thrdHashSize;
            auto hashEnd = std::min(items.size(), hashStart + thrdHashSize);
            hashThrd[pid] = std::thread([&items, &mtx_syn, numHashes, &binIdxs, &binIndex, hashingSeed, numBins, &prng, &myMaskBuff, &perm, hashStart, hashEnd]() {
                for (u64 i = hashStart; i < hashEnd; i++) {
                    for (u64 j = 0; j < numHashes; j++) {
                        auto& bid = binIdxs(i, j);
                        if (bid == -1) {
                            for (;;) {
                                bid = prng.get<u64>() % numBins;
                                if (bid != binIdxs(i, (j+1)%numHashes) &&
                                    bid != binIdxs(i, (j+2)%numHashes))
                                    break;
                            }
                        }
                        binIndex[bid].fetch_add(1, std::memory_order::memory_order_release);
                    }
                }
            });
        }
        for (u64 pid = 0; pid < threadNum; pid++) {
            hashThrd[pid].join();
        }

        for (u64 i = 1; i < numBins; i++) {
            binIndex[i] += binIndex[i - 1];
        }
        binIndex[numBins].store(binIndex[numBins - 1]);

        for (u64 pid = 0; pid < threadNum; pid++) {
            auto hashStart = pid * thrdHashSize;
            auto hashEnd = std::min(items.size(), hashStart + thrdHashSize);
            hashThrd[pid] = std::thread([&items, &mtx_syn, &binIdx, &binHash, numHashes, &binIdxs, &binIndex, hashingSeed, numBins, &prng, &myMaskBuff, &perm, hashStart, hashEnd]() {
                for (u64 i = hashStart; i < hashEnd; i++) {
                    for (u64 j = 0; j < numHashes; j++) {
                        auto bid = binIdxs(i, j);
                        if (bid == -1) std::cout << "error" << std::endl;
                        auto tIndex = binIndex[bid].fetch_add(-1, std::memory_order::memory_order_release);
                        binIdx[tIndex - 1] = i;
                        binHash[tIndex - 1] = j;
                    }
                }
            });
        }
        for (u64 pid = 0; pid < threadNum; pid++) {
            hashThrd[pid].join();
        }
    }


    void MKkrtPsiSender::sendInput(span<block> inputs, span<Channel> chls, span<Channel> mchls)
    {
        if (inputs.size() != mSenderSize)
            throw std::runtime_error("rt error at " LOCATION);

        setTimePoint("kkrt.S Online.online start");

        u64 maskSize = u64(mStatSecParam + std::log2(mSenderSize * mRecverSize) + 7) / 8; //by byte
        auto numBins = mParams.numBins();

        setTimePoint("kkrt.S Online.hashing start");

        std::vector<std::atomic<u64>> binIndex(numBins + 1);
        std::vector<u64> binIdx(mParams.mNumHashes * mSenderSize);
        std::vector<u8> binHash(mParams.mNumHashes * mSenderSize);
        hashBinItems(inputs, mHashingSeed, numBins, mPrng, Matrix<u8>(), mPermute, mParams.mNumHashes, binIndex, binIdx, binHash, mchls.size());

        setTimePoint("kkrt.S Online.linear start");
        std::thread oprfThrd[chls.size()];
        u64 thrdBinSize = std::ceil(1.0 * numBins / chls.size());
        for (u64 pid = 0; pid < chls.size(); pid++) {
            auto binStart = pid * thrdBinSize;
            auto binEnd = std::min(numBins, binStart + thrdBinSize);
            oprfThrd[pid] = std::thread([pid, binStart, &chls, &mchls, binEnd, &inputs, maskSize, this, &binIndex, &binIdx, &binHash]() {
                std::atomic<u64> recvedIdx(binStart);
                std::mutex mtx_syn, mtx_que;
                std::condition_variable cv_syn;
                std::queue<u8 *> recvQue;
                u64 corByte = sizeof(block) * mOtSenders[pid].mGens.size() / 128;
                auto thrd = std::thread([&]() {
                    while (recvedIdx < binEnd)
                    {
                        auto currentStepSize = std::min(stepSize, binEnd - recvedIdx);
                        u8* buffer = new u8[currentStepSize * corByte];
                        // recv指定长度
                        chls[pid].recv(buffer, currentStepSize * corByte);

                        mtx_que.lock();
                        recvQue.push(buffer);
                        mtx_que.unlock();

                        recvedIdx.fetch_add(currentStepSize, std::memory_order::memory_order_release);
                        cv_syn.notify_one();
                    }
                });
                std::unique_lock<std::mutex> lck(mtx_syn);

                Matrix<u8> myMaskBuff(mParams.mNumHashes, stepSize * maskSize + 1);
                Matrix<u64> buffMask(mParams.mNumHashes, 1);
                memset(buffMask.data(), 0, sizeof(u64) * mParams.mNumHashes);

                for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize) {
                    cv_syn.wait(lck, [stepIdx, &recvedIdx]{
                        return stepIdx < recvedIdx.load(std::memory_order::memory_order_acquire);
                    });
                    auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
                    init_ot(currentStepSize, prngs[pid], chls[pid], mOtSenders[pid]);
                    mtx_que.lock();
                    u8 * buffer = recvQue.front();
                    recvQue.pop();
                    mtx_que.unlock();

                    u64 otCorStride = mOtSenders[pid].mCorrectionVals.stride();
                    auto dest = mOtSenders[pid].mCorrectionVals.begin() + (mOtSenders[pid].mCorrectionIdx * otCorStride);
                    for (int i = 0; i < currentStepSize; i++) {
                        memcpy((u8*)&*dest, buffer + i * corByte, corByte);
                        dest += otCorStride;
                    }
                    mOtSenders[pid].mCorrectionIdx += currentStepSize;

                    delete[] buffer;

                    auto stepEnd = stepIdx + currentStepSize;
                    for (u64 bIdx = stepIdx; bIdx < stepEnd; bIdx++)
                    {
                        for (u64 start = binIndex[bIdx]; start < binIndex[bIdx + 1]; start++) {
                            auto inputIdx = binIdx[start];
                            auto inputHash = binHash[start];
                            u8* dest = (u8*)&*(myMaskBuff.data() + myMaskBuff.stride() * inputHash + buffMask(inputHash, 0) * maskSize);
                            mOtSenders[pid].encode(bIdx - stepIdx, &inputs[inputIdx],
                                    dest, maskSize);
                            buffMask(inputHash, 0)++;
                            if (buffMask(inputHash, 0) == stepSize) {
                                myMaskBuff(inputHash, stepSize * maskSize) = inputHash;
                                mchls[pid].asyncSendCopy(myMaskBuff.data() + myMaskBuff.stride() * inputHash, stepSize * maskSize + 1);
                                buffMask(inputHash, 0) = 0;
                            }
                        }
                    }
                }

                for (u64 inputHash = 0; inputHash < mParams.mNumHashes; inputHash++) {
                    u8* dest = (u8*)&*(myMaskBuff.data() + myMaskBuff.stride() * inputHash + buffMask(inputHash, 0) * maskSize);
                    memset(dest, 0, maskSize);
                    myMaskBuff(inputHash, stepSize * maskSize) = inputHash;
                    mchls[pid].asyncSendCopy(myMaskBuff.data() + myMaskBuff.stride() * inputHash, stepSize * maskSize + 1);
                }


                thrd.join();
            });
        }
        for (u64 pid = 0; pid < chls.size(); pid++) {
            oprfThrd[pid].join();
        }

        setTimePoint("kkrt.S Online.done start");

    }

}


#endif

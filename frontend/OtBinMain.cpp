#include "bloomFilterMain.h"
#include "cryptoTools/Network/Endpoint.h" 

#include "libPSI/MPSI/Rr17/Rr17a/Rr17aMPsiReceiver.h"
#include "libPSI/MPSI/Rr17/Rr17a/Rr17aMPsiSender.h"
#include "libPSI/MPSI/Rr17/Rr17b/Rr17bMPsiReceiver.h"
#include "libPSI/MPSI/Rr17/Rr17b/Rr17bMPsiSender.h"


#include "libPSI/MPSI/Grr18/Grr18MPsiReceiver.h"
#include "libPSI/MPSI/Grr18/Grr18MPsiSender.h"

#include "libPSI/PSI/Kkrt/KkrtPsiReceiver.h"
#include "libPSI/PSI/Kkrt/KkrtPsiSender.h"

#include "libPSI/PSI/MKkrt/MKkrtPsiReceiver.h"
#include "libPSI/PSI/MKkrt/MKkrtPsiSender.h"

#include "libPSI/PSI/Cm20/Cm20PsiReceiver.h"
#include "libPSI/PSI/Cm20/Cm20PsiSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "cryptoTools/Common/Defines.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtReceiver.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtSender.h"

#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>
u8 dummy[1];

#define OOS

void rr17aSend(
    LaunchParams& params)
{
#ifdef ENABLE_RR17_PSI
    setThreadName("CP_Test_Thread");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);

            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::vector<block> set(setSize);
                    prng.get(set.data(), set.size());

#ifdef OOS
                    OosNcoOtReceiver otRecv;
                    OosNcoOtSender   otSend;
#else
                    KkrtNcoOtReceiver otRecv;
                    KkrtNcoOtSender otSend;
#endif
                    Rr17aMPsiSender sendPSIs;

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.init(setSize, params.mStatSecParam, sendChls, otSend, otRecv, prng.get<block>(), ss, params.mBitSize);

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.sendInput(set, sendChls);

                    u64 dataSent = 0;
                    for (u64 g = 0; g < sendChls.size(); ++g)
                    {
                        dataSent += sendChls[g].getTotalDataSent();
                    }

                    for (u64 g = 0; g < sendChls.size(); ++g)
                        sendChls[g].resetStats();
                }
            }
        }
    }
#else
    std::cout << Color::Red << "RR17 PSI is not enabled" << std::endl << Color::Default;
#endif
}

void rr17aRecv(
    LaunchParams& params)
{
#ifdef ENABLE_RR17_PSI
    setThreadName("CP_Test_Thread");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);


            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::string tag("RR17a");

                    std::vector<block> sendSet(setSize), recvSet(setSize);
                    for (u64 i = 0; i < setSize; ++i)
                    {
                        sendSet[i] = recvSet[i] = prng.get<block>();
                    }


#ifdef OOS
                    OosNcoOtReceiver otRecv;
                    OosNcoOtSender   otSend;
#else
                    KkrtNcoOtReceiver otRecv;
                    KkrtNcoOtSender otSend;
#endif
                    Rr17aMPsiReceiver recvPSIs;
                    recvPSIs.setTimer(gTimer);

                    chls[0].recv(dummy, 1);
                    gTimer.reset();
                    chls[0].asyncSend(dummy, 1);



                    Timer timer;

                    auto start = timer.setTimePoint("start");

                    recvPSIs.init(setSize, params.mStatSecParam, chls, otRecv, otSend, prng.get<block>(), ss, params.mBitSize);

                    chls[0].asyncSend(dummy, 1);
                    chls[0].recv(dummy, 1);
                    auto mid = timer.setTimePoint("init");


                    recvPSIs.sendInput(recvSet, chls);


                    auto end = timer.setTimePoint("done");

                    auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                    auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                    //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                    printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads, ss);


                    if (params.mVerbose)
                    {
                        std::cout << recvPSIs.getTimer() << std::endl;
                    }
                }
            }
        }
    }
#else
    std::cout << Color::Red << "RR17 PSI is not enabled" << std::endl << Color::Default;
#endif
}


void rr17aSend_StandardModel(
    LaunchParams& params)
{
#ifdef ENABLE_RR17_PSI
    setThreadName("CP_Test_Thread");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);

            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::vector<block> set(setSize);
                    prng.get(set.data(), set.size());

                    Rr17NcoOtReceiver otRecv;
                    Rr17NcoOtSender otSend;

                    Rr17aMPsiSender sendPSIs;
                    sendPSIs.setTimer(gTimer);

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.init(setSize, params.mStatSecParam, sendChls, otSend, otRecv, prng.get<block>(), ss, params.mBitSize);

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.sendInput(set, sendChls);

                    u64 dataSent = 0;
                    for (u64 g = 0; g < sendChls.size(); ++g)
                    {
                        dataSent += sendChls[g].getTotalDataSent();
                    }

                    for (u64 g = 0; g < sendChls.size(); ++g)
                        sendChls[g].resetStats();
                }
            }
        }
    }
#else
    std::cout << Color::Red << "RR17 PSI is not enabled" << std::endl << Color::Default;
#endif
}

void rr17aRecv_StandardModel(
    LaunchParams& params)
{
#ifdef ENABLE_RR17_PSI
    setThreadName("CP_Test_Thread");



    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);

            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::string tag("RR17a-sm");

                    std::vector<block> sendSet(setSize), recvSet(setSize);
                    for (u64 i = 0; i < setSize; ++i)
                    {
                        sendSet[i] = recvSet[i] = prng.get<block>();
                    }


                    Rr17NcoOtReceiver otRecv;
                    Rr17NcoOtSender otSend;

                    Rr17aMPsiReceiver recvPSIs;
                    recvPSIs.setTimer(gTimer);


                    chls[0].recv(dummy, 1);
                    gTimer.reset();
                    chls[0].asyncSend(dummy, 1);



                    Timer timer;

                    auto start = timer.setTimePoint("start");

                    recvPSIs.init(setSize, params.mStatSecParam, chls, otRecv, otSend, prng.get<block>(), ss, params.mBitSize);

                    chls[0].asyncSend(dummy, 1);
                    chls[0].recv(dummy, 1);
                    auto mid = timer.setTimePoint("init");


                    recvPSIs.sendInput(recvSet, chls);


                    auto end = timer.setTimePoint("done");

                    auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                    auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                    //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                    printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads);
                }
            }
        }
    }

#else
    std::cout << Color::Red << "RR17 PSI is not enabled" << std::endl << Color::Default;
#endif
}




void rr17bSend(
    LaunchParams& params)
{
#ifdef ENABLE_RR17B_PSI
    setThreadName("CP_Test_Thread");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);

            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::vector<block> set(setSize);
                    prng.get(set.data(), set.size());

                    OosNcoOtSender   otSend;

                    Rr17bMPsiSender sendPSIs;
                    sendPSIs.setTimer(gTimer);

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);
                    gTimer.reset();

                    sendPSIs.init(setSize, params.mStatSecParam, sendChls, otSend, prng.get<block>(), ss, params.mBitSize);

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.sendInput(set, sendChls);

                    u64 dataSent = 0;
                    for (u64 g = 0; g < sendChls.size(); ++g)
                    {
                        dataSent += sendChls[g].getTotalDataSent();
                    }

                    for (u64 g = 0; g < sendChls.size(); ++g)
                        sendChls[g].resetStats();


                    if (params.mVerbose > 1) std::cout << gTimer << std::endl;
                }
            }
        }
    }

#else
    std::cout << Color::Red << "RR17B PSI is not enabled" << std::endl << Color::Default;
#endif
}

void rr17bRecv(
    LaunchParams& params)
{
#ifdef ENABLE_RR17B_PSI
    setThreadName("CP_Test_Thread");

    //LinearCode code;
    //code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.txt");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);


            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::string tag("RR17b");

                    std::vector<block> sendSet(setSize), recvSet(setSize);
                    for (u64 i = 0; i < setSize; ++i)
                    {
                        sendSet[i] = recvSet[i] = prng.get<block>();
                    }


                    OosNcoOtReceiver otRecv;// (code, 40);
                    Rr17bMPsiReceiver recvPSIs;
                    recvPSIs.setTimer(gTimer);


                    chls[0].recv(dummy, 1);
                    gTimer.reset();
                    chls[0].asyncSend(dummy, 1);



                    Timer timer;

                    auto start = timer.setTimePoint("start");

                    recvPSIs.init(setSize, params.mStatSecParam, chls, otRecv, prng.get<block>(), ss, params.mBitSize);

                    chls[0].asyncSend(dummy, 1);
                    chls[0].recv(dummy, 1);
                    auto mid = timer.setTimePoint("init");


                    recvPSIs.sendInput(recvSet, chls);


                    auto end = timer.setTimePoint("done");

                    auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                    auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                    //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                    printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads, ss);
                }
            }
        }
    }

#else
    std::cout << Color::Red << "RR17 PSI is not enabled" << std::endl << Color::Default;
#endif
}




void kkrtSend(
    LaunchParams& params)
{
#ifdef ENABLE_KKRT_PSI
    setThreadName("CP_Test_Thread");

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);
            u64 senderSize, receiverSize;
            senderSize = receiverSize = setSize;
            if (params.mCmd->isSet("ss")) senderSize = params.mCmd->get<u64>("ss");
            if (params.mCmd->isSet("rs")) receiverSize = params.mCmd->get<u64>("rs");

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> set(senderSize);
                prng.get(set.data(), set.size());

                KkrtNcoOtSender otSend;

                KkrtPsiSender sendPSIs;
                sendPSIs.setTimer(gTimer);

                sendChls[0].asyncSend(dummy, 1);
                sendChls[0].recv(dummy, 1);

                sendPSIs.init(senderSize, receiverSize, params.mStatSecParam, sendChls, otSend, prng.get<block>());

                //sendChls[0].asyncSend(dummy, 1);
                //sendChls[0].recv(dummy, 1);

                sendPSIs.sendInput(set, sendChls);

                u64 dataSent = 0;
                for (u64 g = 0; g < sendChls.size(); ++g)
                {
                    dataSent += sendChls[g].getTotalDataSent();
                }

                for (u64 g = 0; g < sendChls.size(); ++g)
                    sendChls[g].resetStats();
            }
        }
    }

#else
    std::cout << Color::Red << "KKRT PSI is not enabled" << std::endl << Color::Default;
#endif
}

void kkrtRecv(
    LaunchParams& params)
{
#ifdef ENABLE_KKRT_PSI
    setThreadName("CP_Test_Thread");

    //LinearCode code;
    //code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");


    PRNG prng(_mm_set_epi32(4253465, 746587658, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);
            u64 senderSize, receiverSize;
            senderSize = receiverSize = setSize;
            if (params.mCmd->isSet("ss")) senderSize = params.mCmd->get<u64>("ss");
            if (params.mCmd->isSet("rs")) receiverSize = params.mCmd->get<u64>("rs");
            std::cout << "senderSize:" << senderSize << std::endl;
            std::cout << "receiverSize:" << receiverSize << std::endl;

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::string tag("kkrt");

                std::vector<block> recvSet(receiverSize);
                for (u64 i = 0; i < receiverSize; ++i)
                {
                    recvSet[i] = prng.get<block>();
                }

                KkrtNcoOtReceiver otRecv;

                KkrtPsiReceiver recvPSIs;
                recvPSIs.setTimer(gTimer);


                chls[0].recv(dummy, 1);
                gTimer.reset();
                chls[0].asyncSend(dummy, 1);



                Timer timer;

                auto start = timer.setTimePoint("start");

                recvPSIs.init(senderSize, receiverSize, params.mStatSecParam, chls, otRecv, prng.get<block>());

                //chls[0].asyncSend(dummy, 1);
                //chls[0].recv(dummy, 1);
                auto mid = timer.setTimePoint("init");


                recvPSIs.sendInput(recvSet, chls);


                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                printTimings(tag, chls, offlineTime, onlineTime, params, receiverSize, numThreads);
            }
        }
    }

#else
    std::cout << Color::Red << "KKRT PSI is not enabled" << std::endl << Color::Default;
#endif
}

void mkkrtSend(
    LaunchParams& params)
{
#ifdef ENABLE_KKRT_PSI
    setThreadName("CP_Test_Thread");

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);
            std::vector<Channel> maskChls = params.getChannels2(cc);
            u64 senderSize, receiverSize;
            senderSize = receiverSize = setSize;
            if (params.mCmd->isSet("ss")) senderSize = params.mCmd->get<u64>("ss");
            if (params.mCmd->isSet("rs")) receiverSize = params.mCmd->get<u64>("rs");

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> sendSet(senderSize);
                for (u64 i = 0; i < senderSize; ++i)
                {
                    sendSet[i] = prng.get<block>();
                    if (i < senderSize / 2) {
                        memset(&sendSet[i], 0, sizeof(block));
                        ((u64 *)&sendSet[i])[0] = i;
                    } 
                }

                MKkrtPsiSender sendPSIs;
                sendPSIs.setTimer(gTimer);

                sendChls[0].asyncSend(dummy, 1);
                sendChls[0].recv(dummy, 1);

                sendPSIs.init(senderSize, receiverSize, params.mStatSecParam, sendChls, prng.get<block>());

                //sendChls[0].asyncSend(dummy, 1);
                //sendChls[0].recv(dummy, 1);

                sendPSIs.sendInput(sendSet, sendChls, maskChls);

                for (u64 g = 0; g < sendChls.size(); ++g) {
                    sendChls[g].resetStats();
                    maskChls[g].resetStats();
                }
            }
        }
    }

#else
    std::cout << Color::Red << "KKRT PSI is not enabled" << std::endl << Color::Default;
#endif
}

void mkkrtRecv(
    LaunchParams& params)
{
#ifdef ENABLE_KKRT_PSI
    setThreadName("CP_Test_Thread");

    //LinearCode code;
    //code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");


    PRNG prng(_mm_set_epi32(4253465, 746587658, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);
            auto mchls = params.getChannels2(numThreads);
            u64 senderSize, receiverSize;
            senderSize = receiverSize = setSize;
            if (params.mCmd->isSet("ss")) senderSize = params.mCmd->get<u64>("ss");
            if (params.mCmd->isSet("rs")) receiverSize = params.mCmd->get<u64>("rs");
            std::cout << "senderSize:" << senderSize << std::endl;
            std::cout << "receiverSize:" << receiverSize << std::endl;

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::string tag("mkkrt");

                std::vector<block> recvSet(receiverSize);
                for (u64 i = 0; i < receiverSize; ++i)
                {
                    recvSet[i] = prng.get<block>();
                    if (i < receiverSize / 2) {
                        memset(&recvSet[i], 0, sizeof(block));
                        ((u64 *)&recvSet[i])[0] = i;
                    } 
                }

                MKkrtPsiReceiver recvPSIs;
                recvPSIs.setTimer(gTimer);


                chls[0].recv(dummy, 1);
                gTimer.reset();
                chls[0].asyncSend(dummy, 1);



                Timer timer;

                auto start = timer.setTimePoint("start");

                recvPSIs.init(senderSize, receiverSize, params.mStatSecParam, chls, prng.get<block>());

                //chls[0].asyncSend(dummy, 1);
                //chls[0].recv(dummy, 1);
                auto mid = timer.setTimePoint("init");


                recvPSIs.sendInput(recvSet, chls, mchls);


                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                printTimings(tag, chls, offlineTime, onlineTime, params, receiverSize, numThreads, 1, &mchls);

                if (recvPSIs.mIntersection.size() != receiverSize / 2) {
                    std::cout << "intersection size " << recvPSIs.mIntersection.size() << " not match" << receiverSize / 2 << std::endl;
                }
                sort(recvPSIs.mIntersection.begin(), recvPSIs.mIntersection.end());
                int i;
                for (i = 0; i < recvPSIs.mIntersection.size(); i++) {
                    if (recvPSIs.mIntersection[i] != i) {
                        break;
                    }
                }
                if (i != recvPSIs.mIntersection.size()) {
                    std::cout << "intersection wrong result" << std::endl;
                } 
            }
        }
    }

#else
    std::cout << Color::Red << "KKRT PSI is not enabled" << std::endl << Color::Default;
#endif
}


void cm20Send(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);
            double scale = params.mBinScaler.size() == 0 ? 1 : params.mBinScaler[0];
            u64 senderSize, receiverSize;
            senderSize = receiverSize = setSize;
            if (params.mCmd->isSet("ss")) senderSize = params.mCmd->get<u64>("ss");
            if (params.mCmd->isSet("rs")) receiverSize = params.mCmd->get<u64>("rs");

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> sendSet(senderSize);
                for (u64 i = 0; i < senderSize; ++i)
                {
                    sendSet[i] = prng.get<block>();
                    if (i < senderSize / 2) {
                        memset(&sendSet[i], 0, sizeof(block));
                        ((u64 *)&sendSet[i])[0] = i;
                    } 
                }

                Cm20PsiSender sendPSIs;
                Timer timer;
                sendPSIs.setTimer(timer);
                auto start = timer.setTimePoint("start");

                sendChls[0].asyncSend(dummy, 1);
                sendChls[0].recv(dummy, 1);

                sendPSIs.init(senderSize, receiverSize, scale, cc, params.mStatSecParam, sendChls, prng.get<block>());

                //sendChls[0].asyncSend(dummy, 1);
                //sendChls[0].recv(dummy, 1);

                sendPSIs.sendInput(sendSet, sendChls);

                for (u64 g = 0; g < sendChls.size(); ++g)
                    sendChls[g].resetStats();
            }
        }
    }
}

void cm20Recv(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    //LinearCode code;
    //code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");


    PRNG prng(_mm_set_epi32(4253465, 746587658, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);
            double scale = params.mBinScaler.size() == 0 ? 1 : params.mBinScaler[0];
            u64 senderSize, receiverSize;
            senderSize = receiverSize = setSize;
            if (params.mCmd->isSet("ss")) senderSize = params.mCmd->get<u64>("ss");
            if (params.mCmd->isSet("rs")) receiverSize = params.mCmd->get<u64>("rs");
            std::cout << "senderSize:" << senderSize << std::endl;
            std::cout << "receiverSize:" << receiverSize << std::endl;
            std::cout << "scale:" << scale << std::endl;

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::string tag("cm20");

                std::vector<block> recvSet(receiverSize);
                for (u64 i = 0; i < receiverSize; ++i)
                {
                    recvSet[i] = prng.get<block>();
                    if (i < receiverSize / 2) {
                        memset(&recvSet[i], 0, sizeof(block));
                        ((u64 *)&recvSet[i])[0] = i;
                    } 
                }

                Cm20PsiReceiver recvPSIs;

                chls[0].recv(dummy, 1);
                gTimer.reset();
                chls[0].asyncSend(dummy, 1);

                Timer timer;
                recvPSIs.setTimer(timer);
                auto start = timer.setTimePoint("start");

                recvPSIs.init(senderSize, receiverSize, scale, numThreads, params.mStatSecParam, chls, prng.get<block>());

                //chls[0].asyncSend(dummy, 1);
                //chls[0].recv(dummy, 1);
                auto mid = timer.setTimePoint("inited");


                recvPSIs.sendInput(recvSet, chls);

                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                printTimings(tag, chls, offlineTime, onlineTime, params, receiverSize, numThreads);

                if (recvPSIs.mIntersection.size() != receiverSize / 2) {
                    std::cout << "intersection size " << recvPSIs.mIntersection.size() << " not match" << receiverSize / 2 << std::endl;
                }
                sort(recvPSIs.mIntersection.begin(), recvPSIs.mIntersection.end());
                int i;
                for (i = 0; i < recvPSIs.mIntersection.size(); i++) {
                    if (recvPSIs.mIntersection[i] != i) {
                        break;
                    }
                }
                if (i != recvPSIs.mIntersection.size()) {
                    std::cout << "intersection wrong result" << std::endl;
                } 
            }
        }
    }
}

void grr18Send(
    LaunchParams& params)
{
#ifdef ENABLE_GRR_PSI
    setThreadName("send_grr18");

    //_gTimer.setTimePoint("grr18Send()");

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    auto es = params.mCmd->getMany<double>("epsBins");
    for (auto e : es)
    {
        for (auto setSize : params.mNumItems)
        {
            for (auto cc : params.mNumThreads)
            {
                std::vector<Channel> sendChls = params.getChannels(cc);

                for (auto ss : params.mBinScaler)
                {
                    for (u64 jj = 0; jj < params.mTrials; jj++)
                    {
                        std::vector<block> set(setSize);
                        prng.get(set.data(), set.size());

                        OosNcoOtReceiver otRecv;
                        OosNcoOtSender   otSend;

                        Grr18MPsiSender sendPSIs;
                        //sendPSIs.setTimer(_gTimer);

                        sendPSIs.mEpsBins = e;
                        sendPSIs.mEpsMasks = params.mCmd->getOr<double>("epsMasks", 0.1);
                        sendPSIs.mCWThreshold = params.mCmd->getOr<i64>("cw", -1);
                        sendPSIs.mLapPlusBuff = params.mCmd->isSet("lapPlusBuff");

                        sendChls[0].asyncSend(dummy, 1);
                        sendChls[0].recv(dummy, 1);

                        sendPSIs.init(setSize, params.mStatSecParam, sendChls, otSend, otRecv, prng.get<block>(), ss, params.mBitSize);

                        //sendChls[0].asyncSend(dummy, 1);
                        //sendChls[0].recv(dummy, 1);

                        sendPSIs.sendInput(set, sendChls);

                        u64 dataSent = 0;
                        for (u64 g = 0; g < sendChls.size(); ++g)
                        {
                            dataSent += sendChls[g].getTotalDataSent();
                        }

                        for (u64 g = 0; g < sendChls.size(); ++g)
                            sendChls[g].resetStats();

                        if (params.mVerbose)
                        {
                            ostreamLock o(std::cout);

                            std::cout << sendPSIs.mReporting_totalMaskCount << " / " << sendPSIs.mReporting_totalRealMaskCount << " =  total / real masks" << std::endl;

                        }
                    }
                }
            }
        }
    }

#else
    std::cout << Color::Red << "GRR PSI is not enabled" << std::endl << Color::Default;
#endif
}

void grr18Recv(
    LaunchParams& params)
{
#ifdef ENABLE_GRR_PSI
    setThreadName("recv_grr18");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    auto es = params.mCmd->getMany<double>("epsBins");
    for (auto e : es)
    {
        std::cout << " e " << e << std::endl;
        for (auto setSize : params.mNumItems)
        {
            for (auto numThreads : params.mNumThreads)
            {
                auto chls = params.getChannels(numThreads);


                for (auto ss : params.mBinScaler)
                {

                    for (u64 jj = 0; jj < params.mTrials; jj++)
                    {
                        std::string tag("grr18");

                        std::vector<block> sendSet(setSize), recvSet(setSize);
                        for (u64 i = 0; i < setSize; ++i)
                        {
                            sendSet[i] = recvSet[i] = prng.get<block>();
                        }


                        OosNcoOtReceiver otRecv;
                        OosNcoOtSender   otSend;

                        Grr18MPsiReceiver recvPSIs;
                        Timer timer;
                        recvPSIs.setTimer(timer);

                        recvPSIs.mEpsBins = e;
                        recvPSIs.mEpsMasks = params.mCmd->getOr<double>("epsMasks", 0.1);
                        recvPSIs.mLapPlusBuff = params.mCmd->isSet("lapPlusBuff");

                        chls[0].recv(dummy, 1);

                        chls[0].asyncSend(dummy, 1);




                        auto start = timer.setTimePoint("start");

                        recvPSIs.init(setSize, params.mStatSecParam, chls, otRecv, otSend, prng.get<block>(), ss, params.mBitSize);

                        //chls[0].asyncSend(dummy, 1);
                        //chls[0].recv(dummy, 1);
                        auto mid = timer.setTimePoint("init");


                        recvPSIs.sendInput(recvSet, chls);


                        auto end = timer.setTimePoint("done");

                        auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                        auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                        //auto byteSent = chls[0]->getTotalDataSent() *chls.size();
                        ostreamLock o(std::cout);
                        printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads, ss);

                        if (params.mVerbose)
                        {
                            std::cout << recvPSIs.getTimer() << std::endl;


                        }
                        auto load = recvPSIs.mTotalLoad->load() / double(recvPSIs.mBins.mBinCount);
                        auto real = setSize / recvPSIs.mBins.mBinCount;

                            std::cout << "total noisy load: " << load << " vs " << real << ". rr17a has " << recvPSIs.mBins.mMaxBinSize << std::endl;
                    }
                }
            }
        }
    }

#else
    std::cout << Color::Red << "GRR PSI is not enabled" << std::endl << Color::Default;
#endif
}
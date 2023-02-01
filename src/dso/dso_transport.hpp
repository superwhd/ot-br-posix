#include <arpa/inet.h>
#include <map>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <vector>

#include <cassert>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "common/code_utils.hpp"
#include "openthread/logging.h"
#include "openthread/message.h"
#include "openthread/platform/dso_transport.h"

#ifndef OTBR_AGENT_APPLICATION_HPP_
#define OTBR_AGENT_APPLICATION_HPP_

namespace otbr {
namespace dso {

// TODO: queue tx packets
const char *MbedErrorToString(int aError)
{
    static char errBuf[500];
    mbedtls_strerror(aError, errBuf, sizeof(errBuf));
    return errBuf;
}

class DsoConnection : NonCopyable
{
public:
    ~DsoConnection()
    {
        mbedtls_net_free(&mCtx);
        sMap.erase(mConnection);
    }

    otError Connect(const otSockAddr *aPeerSockAddr)
    {
        otError error = OT_ERROR_NONE;
        int     ret;
        char buf[OT_IP6_ADDRESS_STRING_SIZE];

        mPeerSockAddr = *aPeerSockAddr;
        std::string portString = std::to_string(aPeerSockAddr->mPort);

        otIp6AddressToString(&aPeerSockAddr->mAddress, buf, sizeof(buf));
        otbrLogInfo("###### connecting to : %s %s", buf, portString.c_str());

        if ((ret = mbedtls_net_connect(&mCtx, buf, portString.c_str(), MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            otbrLogInfo("address: %s, port: %u", buf, aPeerSockAddr->mPort);
            otbrLogInfo("mbedtls net connect failed: %s", MbedErrorToString(ret));
            error = OT_ERROR_FAILED;
            ExitNow();
        }

        VerifyOrExit((ret = mbedtls_net_set_nonblock(&mCtx)) == 0, error = OT_ERROR_FAILED);
        otbrLogInfo("###### mbedtls net connect succeeded: %s", MbedErrorToString(ret));
        otPlatDsoHandleConnected(mConnection);
        mConnected = true;

    exit:
        if (error != OT_ERROR_NONE)
        {
            otbrLogInfo("???? mbedtls net connect failed: %s", MbedErrorToString(ret));
        }
        return error;
    }

    void Send(otMessage *aMessage)
    {
        uint8_t buf[1600];
        auto    len = otMessageRead(aMessage, 0, buf + 2, sizeof(buf) - 2);
        //        otDumpInfoPlat("going to send DSO payload", buf, len);
        uint16_t size = otMessageGetLength(aMessage);
        otbrLogInfo("Write: size = %hu", size);
        //        size = Encoding::BigEndian::HostSwap16(size);
        size = htons(size);
        memcpy(buf, &size, 2);
        len += 2;
        // TODO: handle insufficient buffer size
        int err = mbedtls_net_send(&mCtx, buf, len);
        if (err < 0)
        {
            otbrLogInfo("failed to send message: %s", MbedErrorToString(err));
        }
        else
        {
            otDumpInfoPlat("@@@@@@@ sending DSO message: ", buf, len);
        }
    }

    void HandleReceive()
    {
        int  ret;

        VerifyOrExit(mConnected);
        ret = mbedtls_net_recv(&mCtx, mBuffer + mBufferEnd, sizeof(mBuffer) - mBufferEnd);
        if (ret < 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ)
            {
                otbrLogInfo("failed to receive message: %s", MbedErrorToString(ret));
            }
            ExitNow();
        }
        if (ret == 0)
        {
            ExitNow();
        }
        otDumpInfoPlat("Received DSO message: ", mBuffer + mBufferEnd, ret);
        mBufferEnd += ret;

        while (true)
        {
            if (!mPendingMessage)
            {
                assert(mWantMessageSize == 0);
                if (static_cast<int32_t>(mBufferEnd) - mBufferBegin >= static_cast<int32_t>(sizeof(uint16_t)))
                {
                    mWantMessageSize = htons(*(reinterpret_cast<uint16_t *>(mBuffer + mBufferBegin)));
                    //                            mWantMessageSize =
                    //                        Encoding::BigEndian::HostSwap16(*(reinterpret_cast<uint16_t *>(mBuffer +
                    //                        mBufferBegin)));
                    if (mWantMessageSize == 0)
                    {
                        Disconnect(OT_PLAT_DSO_DISCONNECT_MODE_FORCIBLY_ABORT);
                        ExitNow();
                    }
                    mBufferBegin += sizeof(uint16_t);
                    VerifyOrDie(mPendingMessage = otIp6NewMessage(otPlatDsoGetInstance(mConnection), nullptr), 1);
                    assert(otMessageGetLength(mPendingMessage) == 0);
                }
                else
                {
                    break;
                }
            }
            otbrLogInfo("Read: mWantMessageSize = %lu mBufferBegin = %hu mBufferEnd = %hu", mWantMessageSize,
                        mBufferBegin, mBufferEnd);
            int32_t readLen = std::min(static_cast<int32_t>(mWantMessageSize) - otMessageGetLength(mPendingMessage),
                                       static_cast<int32_t>(mBufferEnd) - mBufferBegin);
            VerifyOrDie(readLen >= 0, 1);
            VerifyOrDie(otMessageAppend(mPendingMessage, mBuffer + mBufferBegin, readLen) == OT_ERROR_NONE, 1);
            mBufferBegin += readLen;
            if (otMessageGetLength(mPendingMessage) == mWantMessageSize)
            {
                otbrLogInfo("handle DSO receive: %lu", mWantMessageSize);
                otPlatDsoHandleReceive(mConnection, mPendingMessage);
                mPendingMessage  = nullptr;
                mWantMessageSize = 0;
            }
            if (mBufferBegin == mBufferEnd)
            {
                mBufferBegin = mBufferEnd = 0;
                break;
            }
        }
    exit:
        return;
    }

    void Disconnect(otPlatDsoDisconnectMode aMode)
    {
        OT_UNUSED_VARIABLE(aMode);
        switch (aMode)
        {
        case OT_PLAT_DSO_DISCONNECT_MODE_FORCIBLY_ABORT:
            mbedtls_net_close(&mCtx);
            break;
        case OT_PLAT_DSO_DISCONNECT_MODE_GRACEFULLY_CLOSE:
            mbedtls_net_close(&mCtx);
            break;
        default:
            otbrLogInfo("unknown disconnection way");
            break;
        }
        mConnected = false;
        sMap.erase(mConnection);
        otPlatDsoHandleDisconnected(mConnection, aMode);
    }

    static DsoConnection *Find(otPlatDsoConnection *aConnection)
    {
        auto it = sMap.find(aConnection);
        if (it != sMap.end())
        {
            return it->second;
        }
        return nullptr;
    }

    static DsoConnection *FindOrCreate(otPlatDsoConnection *aConnection)
    {
        DsoConnection *&ret = sMap[aConnection];
        if (!ret)
        {
            ret = new DsoConnection(aConnection);
        }
        return ret;
    }

    static void ProcessAll()
    {
        std::vector<DsoConnection *> connections;
        connections.reserve(sMap.size());
        for (auto &conn : sMap)
        {
            connections.push_back(conn.second);
        }
        for (const auto &conn : connections)
        {
            conn->HandleReceive();
        }
    }

    static DsoConnection *Create(otPlatDsoConnection *aConnection, mbedtls_net_context aCtx = {})
    {
        return new DsoConnection(aConnection, aCtx);
    }

    static std::map<otPlatDsoConnection *, DsoConnection *> sMap;

    bool mConnected = false;

private:
    explicit DsoConnection(otPlatDsoConnection *aConnection, mbedtls_net_context aCtx = {})
        : mConnection(aConnection)
        , mCtx(aCtx)
    {
        OT_UNUSED_VARIABLE(mPeerSockAddr);
        sMap[mConnection] = this;

        otbrLogInfo("!!! connection recorded !!!!");
    }

    otPlatDsoConnection *mConnection;
    otSockAddr           mPeerSockAddr{};
    otMessage           *mPendingMessage  = nullptr;
    size_t               mWantMessageSize = 0;
    uint16_t             mBufferBegin     = 0;
    uint16_t             mBufferEnd       = 0;
    uint8_t              mBuffer[2048];
    mbedtls_net_context  mCtx;
};

} // namespace dso
} // namespace otbr

#endif // OTBR_AGENT_APPLICATION_HPP_

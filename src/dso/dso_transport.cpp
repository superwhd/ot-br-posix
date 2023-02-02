/*
 *    Copyright (c) 2023, The OpenThread Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

#include "openthread/platform/dso_transport.h"
#include "dso_transport.hpp"
#include <memory>
#include "mbedtls/net_sockets.h"
#include "openthread/openthread-system.h"

static otbr::dso::DsoAgent *sDsoAgent = nullptr;

// TODO ensure the socket is closed when disabled
extern "C" void otPlatDsoEnableListening(otInstance *aInstance, bool aEnabled)
{
    sDsoAgent->SetEnabled(aInstance, aEnabled);
}

extern "C" void otPlatDsoConnect(otPlatDsoConnection *aConnection, const otSockAddr *aPeerSockAddr)
{
    auto conn = sDsoAgent->FindOrCreate(aConnection);
    conn->Connect(aPeerSockAddr);
}

extern "C" void otPlatDsoSend(otPlatDsoConnection *aConnection, otMessage *aMessage)
{
    OT_UNUSED_VARIABLE(aConnection);
    OT_UNUSED_VARIABLE(aMessage);

    auto conn = sDsoAgent->Find(aConnection);
    otbrLogInfo("finding conn");
    VerifyOrExit(conn != nullptr);
    otbrLogInfo("found conn");
    conn->Send(aMessage);

exit:
    otMessageFree(aMessage);
}

extern "C" void otPlatDsoDisconnect(otPlatDsoConnection *aConnection, otPlatDsoDisconnectMode aMode)
{
    OT_UNUSED_VARIABLE(aConnection);
    OT_UNUSED_VARIABLE(aMode);
    auto conn = sDsoAgent->Find(aConnection);

    VerifyOrExit(conn != nullptr);
    conn->Disconnect(aMode);

    sDsoAgent->Remove(aConnection);

exit:
    return;
}

extern "C" void platformDsoProcess(otInstance *aInstance)
{
    //    otbr::dso::DsoConnection::ProcessAll();
    sDsoAgent->ProcessOutgoingConnections();
    sDsoAgent->ProcessIncomingConnections(aInstance);
}

namespace otbr {
namespace dso {
const char *MbedErrorToString(int aError)
{
    static char errBuf[500];
    mbedtls_strerror(aError, errBuf, sizeof(errBuf));
    return errBuf;
}

DsoAgent::DsoAgent(void)
{
    sDsoAgent = this;
}

DsoAgent::DsoConnection *DsoAgent::Find(otPlatDsoConnection *aConnection)
{
    DsoConnection *ret = nullptr;
    auto           it  = mMap.find(aConnection);

    if (it != mMap.end())
    {
        ret = it->second.get();
    }

    return ret;
}

DsoAgent::DsoConnection *DsoAgent::FindOrCreate(otPlatDsoConnection *aConnection, mbedtls_net_context aCtx)
{
    auto &ret = mMap[aConnection];
    if (!ret)
    {
        ret = std::unique_ptr<DsoConnection>(new DsoConnection(aConnection, aCtx));
    }
    return ret.get();
}

void DsoAgent::ProcessOutgoingConnections()
{
    std::vector<DsoConnection *> connections;
    connections.reserve(mMap.size());
    for (auto &conn : mMap)
    {
        connections.push_back(conn.second.get());
    }
    for (const auto &conn : connections)
    {
        otbrLogInfo("processing connection: ");
        conn->HandleReceive();
    }
}

void DsoAgent::ProcessIncomingConnections(otInstance *aInstance)
{
    VerifyOrExit(mListeningEnabled);

    while (true)
    {
        mbedtls_net_context  incomingCtx;
        uint8_t              incomingAddrBuf[sizeof(sockaddr_in6)];
        size_t               len = 0;
        otSockAddr           addr;
        in6_addr            *addrIn6;
        otPlatDsoConnection *conn;

        int ret = mbedtls_net_accept(&mListeningCtx, &incomingCtx, &incomingAddrBuf, sizeof(incomingAddrBuf), &len);

        VerifyOrExit(ret != MBEDTLS_ERR_SSL_WANT_READ);
        VerifyOrExit(ret == 0, otbrLogInfo("!!!!! error accepting connection: %s", otbr::dso::MbedErrorToString(ret)));

        otbrLogInfo("!!!!! address size===== %ld", len);

        if (mbedtls_net_set_nonblock(&incomingCtx))
        {
            continue;
        }

        if (len == OT_IP6_ADDRESS_SIZE)
        { // TODO: the way of handling addr may be wrong
            Ip6Address address;

            addrIn6 = reinterpret_cast<in6_addr *>(incomingAddrBuf);
            memcpy(&addr.mAddress.mFields.m8, addrIn6, len);
            address.CopyFrom(*addrIn6);

            otbrLogInfo("!!!!! address ===== %s", address.ToString().c_str());
            addr.mPort = 0; // TODO
        }
        else
        {
            otbrLogInfo("!!!!! unknown address type !!!! ");
            continue;
        }
        conn = otPlatDsoAccept(aInstance, &addr);

        if (conn != nullptr)
        {
            mMap[conn]             = MakeUnique<DsoConnection>(conn, incomingCtx);
            mMap[conn]->mConnected = true;
            otPlatDsoHandleConnected(conn);
        }
        else
        {
            char buf[50];
            otIp6AddressToString(reinterpret_cast<otIp6Address *>(&addr.mAddress), buf, sizeof(buf));
            otbrLogInfo("!!!! failed to accept connection: %s %d", buf, addr.mPort);
        }
    }
exit:
    return;
}

void DsoAgent::Enable(otInstance *aInstance)
{
    OTBR_UNUSED_VARIABLE(aInstance);

    VerifyOrExit(!mListeningEnabled);

    mListeningCtx.fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    otbrLogInfo("!!!!!!!! ifrname %s", otSysGetInfraNetifName());
    int ret;
    if ((ret = setsockopt(mListeningCtx.fd, SOL_SOCKET, SO_BINDTODEVICE, otSysGetInfraNetifName(),
                          strlen(otSysGetInfraNetifName()))) < 0)
    {
        perror("Server-setsockopt() error for SO_BINDTODEVICE");
        printf("Server-setsockopt() error for SO_BINDTODEVICE %s\n", strerror(errno));
        std::abort();
    }
    int n;
    if (setsockopt(mListeningCtx.fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&n, sizeof(n)) != 0)
    {
        otbrLogInfo("[srpl] Failed to bind socket");
        std::abort();
    }
    sockaddr_in6 sockAddr;
    sockAddr.sin6_family = AF_INET6;
    sockAddr.sin6_addr   = in6addr_any;
    sockAddr.sin6_port   = htons(kListeningPort);
    //        sockAddr.sin6_port   = ot::Encoding::BigEndian::HostSwap16(kListeningPort);
    otbrLogInfo("INFRA INTERFACE: %s port = %d", otSysGetInfraNetifName(), sockAddr.sin6_port);

    if (bind(mListeningCtx.fd, (struct sockaddr *)&sockAddr, sizeof(sockAddr)) != 0)
    {
        otbrLogInfo("[srpl] Failed to bind socket");
        std::abort();
        //            DieNow(OT_EXIT_ERROR_ERRNO);
    }
    mbedtls_net_set_nonblock(&mListeningCtx);

    if (listen(mListeningCtx.fd, 10) != 0)
    {
        otbrLogInfo("[srpl] Failed to listen on socket");
        std::abort();
        //            DieNow(OT_EXIT_ERROR_ERRNO);
    }
    otbrLogInfo("Listening socket created!!!");

    mListeningEnabled = true;

exit:
    return;
}

void DsoAgent::Disable(otInstance *aInstance)
{
    OTBR_UNUSED_VARIABLE(aInstance);

    VerifyOrExit(mListeningEnabled);

    mbedtls_net_close(&mListeningCtx);
    mMap.clear();
    mListeningEnabled = false;

exit:
    return;
}

void DsoAgent::SetEnabled(otInstance *aInstance, bool aEnabled)
{
    if (aEnabled)
    {
        Enable(aInstance);
    }
    else
    {
        Disable(aInstance);
    }
}

void DsoAgent::Remove(otPlatDsoConnection *aConnection)
{
    mMap.erase(aConnection);
}

otError DsoAgent::DsoConnection::Connect(const otSockAddr *aPeerSockAddr)
{
    otError error = OT_ERROR_NONE;
    int     ret;
    char    buf[OT_IP6_ADDRESS_STRING_SIZE];

    mPeerSockAddr          = *aPeerSockAddr;
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

void DsoAgent::DsoConnection::Send(otMessage *aMessage)
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

void DsoAgent::DsoConnection::HandleReceive(void)
{
    int ret;

    otbrLogInfo("handle receive fd: %d Connected: %d", mCtx.fd, mConnected);
    VerifyOrExit(mConnected);

    ret = mbedtls_net_recv(&mCtx, mBuffer + mBufferEnd, sizeof(mBuffer) - mBufferEnd);
    otbrLogInfo("handle receive fd: %d Connected: %d ret: %d", mCtx.fd, mConnected, ret);
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
                mWantMessageSize = ntohs(*(reinterpret_cast<uint16_t *>(mBuffer + mBufferBegin)));
                //                            mWantMessageSize =
                //                        Encoding::BigEndian::HostSwap16(*(reinterpret_cast<uint16_t *>(mBuffer
                //                        + mBufferBegin)));
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
        otbrLogInfo("Read: mWantMessageSize = %lu mBufferBegin = %hu mBufferEnd = %hu", mWantMessageSize, mBufferBegin,
                    mBufferEnd);
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

void DsoAgent::DsoConnection::Disconnect(otPlatDsoDisconnectMode aMode)
{
    OT_UNUSED_VARIABLE(aMode);
    switch (aMode)
    {
        // TODO handle them properly
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
    mCtx       = {};
    // In particular, calling `otPlatDsoDisconnect()`
    //  * MUST NOT trigger the callback `otPlatDsoHandleDisconnected()`.
    //        otPlatDsoHandleDisconnected(mConnection, aMode);
}

} // namespace dso
} // namespace otbr

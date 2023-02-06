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

#if OTBR_ENABLE_DNS_DSO

#define OTBR_LOG_TAG "DSO"

#include "dso_transport.hpp"

#include <cinttypes>
#include <memory>

#include "mbedtls/net_sockets.h"
#include "openthread/openthread-system.h"
#include "openthread/platform/dso_transport.h"

static otbr::dso::DsoAgent *sDsoAgent = nullptr;

extern "C" void otPlatDsoEnableListening(otInstance *aInstance, bool aEnabled)
{
    sDsoAgent->SetEnabled(aInstance, aEnabled);
}

extern "C" void otPlatDsoConnect(otPlatDsoConnection *aConnection, const otSockAddr *aPeerSockAddr)
{
    sDsoAgent->FindOrCreate(aConnection)->Connect(aPeerSockAddr);
}

extern "C" void otPlatDsoSend(otPlatDsoConnection *aConnection, otMessage *aMessage)
{
    auto conn = sDsoAgent->Find(aConnection);

    VerifyOrExit(conn != nullptr);
    conn->Send(aMessage);

exit:
    otMessageFree(aMessage);
}

extern "C" void otPlatDsoDisconnect(otPlatDsoConnection *aConnection, otPlatDsoDisconnectMode aMode)
{
    auto conn = sDsoAgent->Find(aConnection);

    VerifyOrExit(conn != nullptr);
    conn->Disconnect(aMode);

    sDsoAgent->Remove(aConnection);

exit:
    return;
}

extern "C" void platformDsoProcess(otInstance *aInstance)
{
    sDsoAgent->ProcessConnections();
    sDsoAgent->HandleIncomingConnections(aInstance);
}

namespace otbr {
namespace dso {

DsoAgent::DsoAgent(void)
{
    mbedtls_net_init(&mListeningCtx);
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

DsoAgent::DsoConnection *DsoAgent::FindOrCreate(otPlatDsoConnection *aConnection)
{
    auto &ret = mMap[aConnection];

    if (!ret)
    {
        ret = MakeUnique<DsoConnection>(aConnection);
    }

    return ret.get();
}

DsoAgent::DsoConnection *DsoAgent::FindOrCreate(otPlatDsoConnection *aConnection, mbedtls_net_context aCtx)
{
    auto &ret = mMap[aConnection];

    if (!ret)
    {
        ret = MakeUnique<DsoConnection>(aConnection, aCtx);
    }

    return ret.get();
}

void DsoAgent::ProcessConnections(void)
{
    std::vector<DsoConnection *> connections;

    connections.reserve(mMap.size());
    for (auto &conn : mMap)
    {
        connections.push_back(conn.second.get());
    }
    for (const auto &conn : connections)
    {
        conn->HandleReceive();
    }
}

void DsoAgent::HandleIncomingConnections(otInstance *aInstance)
{
    mbedtls_net_context incomingCtx;
    uint8_t             address[sizeof(sockaddr_in6)];
    size_t              len;
    int                 ret = 0;

    VerifyOrExit(mListeningEnabled);

    while (!(ret = mbedtls_net_accept(&mListeningCtx, &incomingCtx, &address, sizeof(address), &len)))
    {
        HandleIncomingConnection(aInstance, incomingCtx, address, len);
    }

    if (ret != MBEDTLS_ERR_SSL_WANT_READ)
    {
        otbrLogWarning("Failed to accept incoming connection: %d", ret);
    }

exit:

    return;
}

void DsoAgent::Enable(otInstance *aInstance)
{
    OTBR_UNUSED_VARIABLE(aInstance);

    constexpr int kOne = 1;
    sockaddr_in6  sockAddr;

    VerifyOrExit(!mListeningEnabled);

    mListeningCtx.fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

    VerifyOrExit(!setsockopt(mListeningCtx.fd, SOL_SOCKET, SO_BINDTODEVICE, otSysGetInfraNetifName(),
                             strlen(otSysGetInfraNetifName())));
    VerifyOrExit(!setsockopt(mListeningCtx.fd, SOL_SOCKET, SO_REUSEADDR, (const uint8_t *)&kOne, sizeof(kOne)));
    VerifyOrExit(!setsockopt(mListeningCtx.fd, SOL_SOCKET, SO_REUSEPORT, (const uint8_t *)&kOne, sizeof(kOne)));

    sockAddr.sin6_family = AF_INET6;
    sockAddr.sin6_addr   = in6addr_any;
    sockAddr.sin6_port   = htons(kListeningPort);
    VerifyOrExit(!bind(mListeningCtx.fd, (struct sockaddr *)&sockAddr, sizeof(sockAddr)));
    VerifyOrExit(!mbedtls_net_set_nonblock(&mListeningCtx));
    VerifyOrExit(!listen(mListeningCtx.fd, kMaxQueuedConnections));

    mListeningEnabled = true;

    otbrLogInfo("DSO socket starts listening");

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
    otError     error = OT_ERROR_NONE;
    int         ret;
    char        addrBuf[OT_IP6_ADDRESS_STRING_SIZE];
    std::string portString;

    VerifyOrExit(!mConnected);

    mPeerSockAddr = *aPeerSockAddr;
    portString    = std::to_string(aPeerSockAddr->mPort);
    otIp6AddressToString(&aPeerSockAddr->mAddress, addrBuf, sizeof(addrBuf));

    otbrLogInfo("Connecting to %s:%s", addrBuf, portString.c_str());

    VerifyOrExit(!(ret = mbedtls_net_connect(&mCtx, addrBuf, portString.c_str(), MBEDTLS_NET_PROTO_TCP)),
                 otbrLogWarning("Failed to connect: %d", ret));
    VerifyOrExit(!(ret = mbedtls_net_set_nonblock(&mCtx)), otbrLogWarning("Failed to set non-blocking: %d", ret));

    otPlatDsoHandleConnected(mConnection);
    mConnected = true;

exit:
    if (!mConnected)
    {
        error = OT_ERROR_FAILED;
    }
    return error;
}

void DsoAgent::DsoConnection::Disconnect(otPlatDsoDisconnectMode aMode)
{
    struct linger l;

    switch (aMode)
    {
    case OT_PLAT_DSO_DISCONNECT_MODE_FORCIBLY_ABORT:
        l.l_onoff  = 1;
        l.l_linger = 0;
        setsockopt(mCtx.fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
        break;
    case OT_PLAT_DSO_DISCONNECT_MODE_GRACEFULLY_CLOSE:
        break;
    default:
        otbrLogWarning("Unknown disconnection mode: %d", aMode);
        break;
    }

    mbedtls_net_close(&mCtx);
    mConnected = false;
    mbedtls_net_init(&mCtx);
}

void DsoAgent::DsoConnection::Send(otMessage *aMessage)
{
    uint16_t             length = otMessageGetLength(aMessage);
    std::vector<uint8_t> buf(length + kTwo);
    uint16_t             lengthInBigEndian = htons(length);

    otbrLogInfo("Sending a message with length %" PRIu16, length);

    memcpy(buf.data(), &lengthInBigEndian, kTwo);
    VerifyOrExit(length == otMessageRead(aMessage, 0, buf.data() + kTwo, length),
                 otbrLogWarning("Failed to read message data"));
    VerifyOrExit(mbedtls_net_send(&mCtx, buf.data(), buf.size()) > 0, otbrLogWarning("Failed to send DSO message"));

    // TODO: May need to keep sending until all the data is sent
exit:
    return;
}

void DsoAgent::DsoConnection::HandleReceive(void)
{
    int     ret;
    uint8_t buf[kRxBufferSize];

    VerifyOrExit(mConnected);

    while (true)
    {
        if (mNeedBytes)
        {
            ret = mbedtls_net_recv(&mCtx, buf, std::min(sizeof(buf), mNeedBytes));
            VerifyOrExit(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != 0);
            VerifyOrExit(ret >= 0, otbrLogWarning("Failed to receive message: %d", ret));

            SuccessOrExit(otMessageAppend(mPendingMessage, buf, ret));
            mNeedBytes -= ret;

            if (!mNeedBytes)
            {
                otPlatDsoHandleReceive(mConnection, mPendingMessage);
                mPendingMessage = nullptr;
            }
        }
        else
        {
            assert(mLengthBuffer.size() < kTwo);
            assert(mPendingMessage == nullptr);

            ret = mbedtls_net_recv(&mCtx, buf, kTwo - mLengthBuffer.size());

            VerifyOrExit(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != 0);
            VerifyOrExit(ret >= 0, otbrLogWarning("Failed to receive message: %d", ret));

            for (int i = 0; i < ret; ++i)
            {
                mLengthBuffer.push_back(buf[i]);
            }
            if (mLengthBuffer.size() == kTwo)
            {
                mNeedBytes      = mLengthBuffer[0] << 8 | mLengthBuffer[1];
                mPendingMessage = otIp6NewMessage(otPlatDsoGetInstance(mConnection), nullptr);
                mLengthBuffer.clear();
            }
        }
    }

exit:
    return;
}

void DsoAgent::HandleIncomingConnection(otInstance         *aInstance,
                                        mbedtls_net_context aCtx,
                                        uint8_t            *aAddress,
                                        size_t              aAddressLength)
{
    otSockAddr           sockAddr;
    otPlatDsoConnection *conn;
    in6_addr            *addrIn6    = nullptr;
    bool                 successful = false;

    VerifyOrExit(!mbedtls_net_set_nonblock(&aCtx), otbrLogWarning("Failed to set the socket as non-blocking"));

    // TODO: support IPv4
    if (aAddressLength == OT_IP6_ADDRESS_SIZE)
    {
        Ip6Address address;

        addrIn6 = reinterpret_cast<in6_addr *>(aAddress);
        memcpy(&sockAddr.mAddress.mFields.m8, addrIn6, aAddressLength);
        sockAddr.mPort = 0; // Mbed TLS doesn't provide the client's port number.

        address.CopyFrom(*addrIn6);
        otbrLogInfo("Receiving connection from %s", address.ToString().c_str());
    }
    else
    {
        otbrLogInfo("Unsupported address length: %zu", aAddressLength);
        ExitNow();
    }

    conn = otPlatDsoAccept(aInstance, &sockAddr);

    VerifyOrExit(conn != nullptr, otbrLogInfo("Failed to accept connection"));

    FindOrCreate(conn, aCtx);
    otPlatDsoHandleConnected(conn);
    successful = true;

exit:
    if (!successful)
    {
        mbedtls_net_close(&aCtx);
    }
}

} // namespace dso
} // namespace otbr

#endif

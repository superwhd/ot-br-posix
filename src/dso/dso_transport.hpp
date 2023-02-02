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

#include <arpa/inet.h>
#include <map>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <vector>

#include <cassert>
#include <list>

#include "common/code_utils.hpp"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "openthread/logging.h"
#include "openthread/message.h"
#include "openthread/platform/dso_transport.h"

#ifndef OTBR_AGENT_DSO_TRANSPORT_HPP_
#define OTBR_AGENT_DSO_TRANSPORT_HPP_

namespace otbr {
namespace dso {

// TODO: queue tx packets
const char *MbedErrorToString(int aError);

class DsoAgent
{
private:
    class DsoConnection;

public:
    explicit DsoAgent(void);

    void Enable(otInstance *aInstance);
    void Disable(otInstance *aInstance);
    void SetEnabled(otInstance *aInstance, bool aEnabled);

    DsoConnection *Find(otPlatDsoConnection *aConnection);
    DsoConnection *FindOrCreate(otPlatDsoConnection *aConnection, mbedtls_net_context aCtx = {});

    void Remove(otPlatDsoConnection *aConnection);

    void ProcessOutgoingConnections();
    void ProcessIncomingConnections(otInstance *aInstance);

private:
    class DsoConnection : NonCopyable
    {
    public:
        DsoConnection(otPlatDsoConnection *aConnection, mbedtls_net_context aCtx)
            : mConnection(aConnection)
            , mCtx(aCtx)
        {
        }
        ~DsoConnection(void) { mbedtls_net_free(&mCtx); }

        otError Connect(const otSockAddr *aPeerSockAddr);

        void Send(otMessage *aMessage);

        void HandleReceive(void);

        void Disconnect(otPlatDsoDisconnectMode aMode);

        bool mConnected = false;

    private:
        otPlatDsoConnection *mConnection;
        otSockAddr           mPeerSockAddr{};
        otMessage           *mPendingMessage  = nullptr;
        size_t               mWantMessageSize = 0;
        uint16_t             mBufferBegin     = 0;
        uint16_t             mBufferEnd       = 0;
        uint8_t              mBuffer[2048];
        mbedtls_net_context  mCtx;
    };

    static constexpr uint16_t kListeningPort = 853;

    bool                mListeningEnabled = false;
    mbedtls_net_context mListeningCtx{};

    std::map<otPlatDsoConnection *, std::unique_ptr<DsoConnection>> mMap;
};

} // namespace dso
} // namespace otbr

#endif //

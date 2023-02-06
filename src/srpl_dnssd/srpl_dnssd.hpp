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

#ifndef OTBR_AGENT_SRPL_DNSSD_HPP_
#define OTBR_AGENT_SRPL_DNSSD_HPP_

#if OTBR_ENABLE_SRP_REPLICATION

#include <openthread/instance.h>

#include "common/types.hpp"
#include "mdns/mdns.hpp"
#include "ncp/ncp_openthread.hpp"

namespace otbr {

namespace SrplDnssd {

/**
 *
 * @addtogroup border-router-srpl-dnssd
 *
 * @brief
 *   This module includes definition for SRPL DNS-SD over mDNS.
 *
 * @{
 */

class SrplDnssd
{
public:
    /**
     * This constructor initializes the SrplDnssd instance.
     *
     * @param aNcp
     * @param aPublisher
     */
    explicit SrplDnssd(Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher);

    void StartBrowse(void);

    void StopBrowse(void);

    void RegisterService(const uint8_t *aTxtData, uint8_t aTxtLength);

    void UnregisterService(void);

private:
    static constexpr const char *kServiceType = "_srpl-tls._tcp";
    static constexpr uint16_t    kPort        = 853;

    using DiscoveredInstanceInfo = otbr::Mdns::Publisher::DiscoveredInstanceInfo;

    bool IsBrowsing(void) const { return mSubscriberId != 0; }

    void OnServiceInstanceResolved(const std::string &aType, const DiscoveredInstanceInfo &aInstanceInfo);

    Ncp::ControllerOpenThread &mNcp;
    Mdns::Publisher           &mPublisher;
    std::string                mServiceInstanceName;
    uint64_t                   mSubscriberId = 0;
};

/**
 * @}
 */

} // namespace SrplDnssd

} // namespace otbr

#endif // OTBR_ENABLE_SRP_REPLICATION

#endif // OTBR_AGENT_SRPL_DNSSD_HPP_
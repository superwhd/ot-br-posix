/*
 *    Copyright (c) 2018, The OpenThread Authors.
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

/**
 * @file
 *   This file implements mDNS publisher based on mDNSResponder.
 */

#define OTBR_LOG_TAG "MDNS"

#include "mdns/mdns_mdnssd.hpp"

#include <algorithm>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/code_utils.hpp"
#include "common/dns_utils.hpp"
#include "common/logging.hpp"
#include "common/time.hpp"
#include "utils/strcpy_utils.hpp"

namespace otbr {

namespace Mdns {

static const char kDomain[] = "local.";

static otbrError DNSErrorToOtbrError(DNSServiceErrorType aError)
{
    otbrError error;

    switch (aError)
    {
    case kDNSServiceErr_NoError:
        error = OTBR_ERROR_NONE;
        break;

    case kDNSServiceErr_NoSuchKey:
    case kDNSServiceErr_NoSuchName:
    case kDNSServiceErr_NoSuchRecord:
        error = OTBR_ERROR_NOT_FOUND;
        break;

    case kDNSServiceErr_Invalid:
    case kDNSServiceErr_BadParam:
    case kDNSServiceErr_BadFlags:
    case kDNSServiceErr_BadInterfaceIndex:
        error = OTBR_ERROR_INVALID_ARGS;
        break;

    case kDNSServiceErr_AlreadyRegistered:
    case kDNSServiceErr_NameConflict:
        error = OTBR_ERROR_DUPLICATED;
        break;

    case kDNSServiceErr_Unsupported:
        error = OTBR_ERROR_NOT_IMPLEMENTED;
        break;

    default:
        error = OTBR_ERROR_MDNS;
        break;
    }

    return error;
}

static const char *DNSErrorToString(DNSServiceErrorType aError)
{
    switch (aError)
    {
    case kDNSServiceErr_NoError:
        return "OK";

    case kDNSServiceErr_Unknown:
        // 0xFFFE FFFF
        return "Unknown";

    case kDNSServiceErr_NoSuchName:
        return "No Such Name";

    case kDNSServiceErr_NoMemory:
        return "No Memory";

    case kDNSServiceErr_BadParam:
        return "Bad Param";

    case kDNSServiceErr_BadReference:
        return "Bad Reference";

    case kDNSServiceErr_BadState:
        return "Bad State";

    case kDNSServiceErr_BadFlags:
        return "Bad Flags";

    case kDNSServiceErr_Unsupported:
        return "Unsupported";

    case kDNSServiceErr_NotInitialized:
        return "Not Initialized";

    case kDNSServiceErr_AlreadyRegistered:
        return "Already Registered";

    case kDNSServiceErr_NameConflict:
        return "Name Conflict";

    case kDNSServiceErr_Invalid:
        return "Invalid";

    case kDNSServiceErr_Firewall:
        return "Firewall";

    case kDNSServiceErr_Incompatible:
        // client library incompatible with daemon
        return "Incompatible";

    case kDNSServiceErr_BadInterfaceIndex:
        return "Bad Interface Index";

    case kDNSServiceErr_Refused:
        return "Refused";

    case kDNSServiceErr_NoSuchRecord:
        return "No Such Record";

    case kDNSServiceErr_NoAuth:
        return "No Auth";

    case kDNSServiceErr_NoSuchKey:
        return "No Such Key";

    case kDNSServiceErr_NATTraversal:
        return "NAT Traversal";

    case kDNSServiceErr_DoubleNAT:
        return "Double NAT";

    case kDNSServiceErr_BadTime:
        // Codes up to here existed in Tiger
        return "Bad Time";

    case kDNSServiceErr_BadSig:
        return "Bad Sig";

    case kDNSServiceErr_BadKey:
        return "Bad Key";

    case kDNSServiceErr_Transient:
        return "Transient";

    case kDNSServiceErr_ServiceNotRunning:
        // Background daemon not running
        return "Service Not Running";

    case kDNSServiceErr_NATPortMappingUnsupported:
        // NAT doesn't support NAT-PMP or UPnP
        return "NAT Port Mapping Unsupported";

    case kDNSServiceErr_NATPortMappingDisabled:
        // NAT supports NAT-PMP or UPnP but it's disabled by the administrator
        return "NAT Port Mapping Disabled";

    case kDNSServiceErr_NoRouter:
        // No router currently configured (probably no network connectivity)
        return "No Router";

    case kDNSServiceErr_PollingMode:
        return "Polling Mode";

    case kDNSServiceErr_Timeout:
        return "Timeout";

    default:
        assert(false);
        return nullptr;
    }
}

PublisherMDnsSd::PublisherMDnsSd(StateCallback aCallback)
    : mHostsRef(nullptr)
    , mState(State::kIdle)
    , mStateCallback(std::move(aCallback))
{
}

PublisherMDnsSd::~PublisherMDnsSd(void)
{
    Stop();
}

otbrError PublisherMDnsSd::Start(void)
{
    mState = State::kReady;
    mStateCallback(State::kReady);
    return OTBR_ERROR_NONE;
}

bool PublisherMDnsSd::IsStarted(void) const
{
    return mState == State::kReady;
}

void PublisherMDnsSd::Stop(void)
{
    VerifyOrExit(mState == State::kReady);

    mServiceRegistrations.clear();

    mHostRegistrations.clear();
    if (mHostsRef != nullptr)
    {
        DNSServiceRefDeallocate(mHostsRef);
        mHostsRef = nullptr;
    }

exit:
    return;
}

void PublisherMDnsSd::Update(MainloopContext &aMainloop)
{
    for (auto &kv : mServiceRegistrations)
    {
        auto serviceReg = std::dynamic_pointer_cast<DnssdServiceRegistration>(kv.second);

        assert(serviceReg->GetServiceRef() != nullptr);

        int fd = DNSServiceRefSockFD(serviceReg->GetServiceRef());

        if (fd != -1)
        {
            FD_SET(fd, &aMainloop.mReadFdSet);
            aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, fd);
        }
    }

    if (mHostsRef != nullptr)
    {
        int fd = DNSServiceRefSockFD(mHostsRef);

        assert(fd != -1);

        FD_SET(fd, &aMainloop.mReadFdSet);

        aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, fd);
    }

    for (Subscription &subscription : mSubscribedServices)
    {
        if (subscription.mServiceRef != nullptr)
        {
            int fd = DNSServiceRefSockFD(subscription.mServiceRef);
            assert(fd != -1);

            FD_SET(fd, &aMainloop.mReadFdSet);
            aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, fd);
        }
    }

    for (Subscription &subscription : mSubscribedHosts)
    {
        if (subscription.mServiceRef != nullptr)
        {
            int fd = DNSServiceRefSockFD(subscription.mServiceRef);
            assert(fd != -1);

            FD_SET(fd, &aMainloop.mReadFdSet);
            aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, fd);
        }
    }
}

void PublisherMDnsSd::Process(const MainloopContext &aMainloop)
{
    std::vector<DNSServiceRef> readyServices;

    for (auto &kv : mServiceRegistrations)
    {
        auto serviceReg = std::dynamic_pointer_cast<DnssdServiceRegistration>(kv.second);
        int  fd         = DNSServiceRefSockFD(serviceReg->GetServiceRef());

        if (FD_ISSET(fd, &aMainloop.mReadFdSet))
        {
            readyServices.push_back(serviceReg->GetServiceRef());
        }
    }

    if (mHostsRef != nullptr)
    {
        int fd = DNSServiceRefSockFD(mHostsRef);

        if (FD_ISSET(fd, &aMainloop.mReadFdSet))
        {
            readyServices.push_back(mHostsRef);
        }
    }

    for (Subscription &subscription : mSubscribedServices)
    {
        if (subscription.mServiceRef != nullptr)
        {
            int fd = DNSServiceRefSockFD(subscription.mServiceRef);
            assert(fd != -1);

            if (FD_ISSET(fd, &aMainloop.mReadFdSet))
            {
                readyServices.push_back(subscription.mServiceRef);
            }
        }
    }

    for (Subscription &service : mSubscribedHosts)
    {
        if (service.mServiceRef != nullptr)
        {
            int fd = DNSServiceRefSockFD(service.mServiceRef);
            assert(fd != -1);

            if (FD_ISSET(fd, &aMainloop.mReadFdSet))
            {
                readyServices.push_back(service.mServiceRef);
            }
        }
    }

    for (DNSServiceRef serviceRef : readyServices)
    {
        DNSServiceErrorType error = DNSServiceProcessResult(serviceRef);

        if (error != kDNSServiceErr_NoError)
        {
            otbrLogWarning("DNSServiceProcessResult failed: %s", DNSErrorToString(error));
        }
    }
}

PublisherMDnsSd::DnssdServiceRegistration::~DnssdServiceRegistration(void)
{
    if (mServiceRef != nullptr)
    {
        DNSServiceRefDeallocate(mServiceRef);
    }
}

PublisherMDnsSd::DnssdHostRegistration::~DnssdHostRegistration(void)
{
    VerifyOrExit(mServiceRef != nullptr && mRecordRef != nullptr);

    if (IsCompleted())
    {
        // The Bonjour mDNSResponder somehow doesn't send goodbye message for the AAAA record when it is
        // removed by `DNSServiceRemoveRecord`. Per RFC 6762, a goodbye message of a record sets its TTL
        // to zero but the receiver should record the TTL of 1 and flushes the cache 1 second later. Here
        // we remove the AAAA record after updating its TTL to 1 second. This has the same effect as
        // sending a goodbye message.
        // TODO: resolve the goodbye issue with Bonjour mDNSResponder.
        int dnsError = DNSServiceUpdateRecord(mServiceRef, mRecordRef, kDNSServiceFlagsUnique, mAddress.size(),
                                              mAddress.data(), /* ttl */ 1);
        otbrLogWarning("Failed to send goodbye message for host %s: %s", MakeFullHostName(mName).c_str(),
                       DNSErrorToString(dnsError));
    }

    DNSServiceRemoveRecord(mServiceRef, mRecordRef, /* flags */ 0);
    // TODO: ?
    // DNSRecordRefDeallocate(mRecordRef);

exit:
    return;
}

Publisher::ServiceRegistrationPtr PublisherMDnsSd::FindServiceRegistration(const DNSServiceRef &aServiceRef)
{
    ServiceRegistrationPtr result = nullptr;

    for (auto &kv : mServiceRegistrations)
    {
        // We are sure that the service registrations must be instances of `DnssdServiceRegistration`.
        auto dnssdServiceReg = std::dynamic_pointer_cast<DnssdServiceRegistration>(kv.second);

        if (dnssdServiceReg != nullptr && dnssdServiceReg->GetServiceRef() == aServiceRef)
        {
            result = dnssdServiceReg;
            break;
        }
    }

    return result;
}

Publisher::HostRegistrationPtr PublisherMDnsSd::FindHostRegistration(const DNSServiceRef &aServiceRef,
                                                                     const DNSRecordRef & aRecordRef)
{
    HostRegistrationPtr result = nullptr;

    for (auto &kv : mHostRegistrations)
    {
        // We are sure that the host registrations must be instances of `DnssdServiceRegistration`.
        auto dnssdHostReg = std::dynamic_pointer_cast<DnssdHostRegistration>(kv.second);

        if (dnssdHostReg != nullptr && dnssdHostReg->GetServiceRef() == aServiceRef &&
            dnssdHostReg->GetRecordRef() == aRecordRef)
        {
            result = dnssdHostReg;
            break;
        }
    }

    return result;
}

void PublisherMDnsSd::HandleServiceRegisterResult(DNSServiceRef         aService,
                                                  const DNSServiceFlags aFlags,
                                                  DNSServiceErrorType   aError,
                                                  const char *          aName,
                                                  const char *          aType,
                                                  const char *          aDomain,
                                                  void *                aContext)
{
    static_cast<PublisherMDnsSd *>(aContext)->HandleServiceRegisterResult(aService, aFlags, aError, aName, aType,
                                                                          aDomain);
}

void PublisherMDnsSd::HandleServiceRegisterResult(DNSServiceRef         aServiceRef,
                                                  const DNSServiceFlags aFlags,
                                                  DNSServiceErrorType   aError,
                                                  const char *          aName,
                                                  const char *          aType,
                                                  const char *          aDomain)
{
    OTBR_UNUSED_VARIABLE(aDomain);

    std::string            type = aType;
    std::string            originalInstanceName;
    ServiceRegistrationPtr serviceReg = FindServiceRegistration(aServiceRef);

    VerifyOrExit(serviceReg != nullptr);

    if (type.back() == '.')
    {
        type.pop_back();
    }

    // mDNSResponder could auto-rename the service instance
    // name when name conflict is detected.
    originalInstanceName = serviceReg->mName;

    otbrLogInfo("Received reply for service %s.%s", originalInstanceName.c_str(), aType);

    if (originalInstanceName != aName)
    {
        otbrLogInfo("Service %s.%s renamed to %s.%s", originalInstanceName.c_str(), aType, aName, aType);
    }

    if (aError == kDNSServiceErr_NoError && (aFlags & kDNSServiceFlagsAdd))
    {
        otbrLogInfo("Successfully registered service %s.%s", originalInstanceName.c_str(), aType);
        serviceReg->Complete(OTBR_ERROR_NONE);
    }
    else
    {
        otbrLogErr("Failed to register service %s.%s: %s", originalInstanceName.c_str(), aType,
                   DNSErrorToString(aError));
        serviceReg->Complete(DNSErrorToOtbrError(aError));
        RemoveServiceRegistration(serviceReg->mName, serviceReg->mType);
    }

exit:
    return;
}

void PublisherMDnsSd::PublishService(const std::string &aHostName,
                                     const std::string &aName,
                                     const std::string &aType,
                                     const SubTypeList &aSubTypeList,
                                     uint16_t           aPort,
                                     const TxtList &    aTxtList,
                                     ResultCallback &&  aCallback)
{
    otbrError            ret   = OTBR_ERROR_NONE;
    int                  error = 0;
    std::vector<uint8_t> txt;
    SubTypeList          sortedSubTypeList = SortSubTypeList(aSubTypeList);
    TxtList              sortedTxtList     = SortTxtList(aTxtList);
    std::string          regType           = MakeRegType(aType, sortedSubTypeList);
    DNSServiceRef        serviceRef        = nullptr;
    std::string          fullHostName;

    if (!aHostName.empty())
    {
        HostRegistrationPtr hostReg = Publisher::FindHostRegistration(aHostName);

        // Make sure that the host has been published.
        VerifyOrExit(hostReg != nullptr, ret = OTBR_ERROR_INVALID_ARGS);
        fullHostName = MakeFullHostName(aHostName);
    }

    aCallback = HandleDuplicateServiceRegistration(aHostName, aName, aType, sortedSubTypeList, aPort, sortedTxtList,
                                                   std::move(aCallback));
    if (aCallback.IsNull())
    {
        ExitNow();
    }

    SuccessOrExit(ret = EncodeTxtData(aTxtList, txt));
    SuccessOrExit(error = DNSServiceRegister(&serviceRef, /* flags */ 0, kDNSServiceInterfaceIndexAny, aName.c_str(),
                                             regType.c_str(), /* domain */ nullptr,
                                             !aHostName.empty() ? fullHostName.c_str() : nullptr, htons(aPort),
                                             txt.size(), txt.data(), HandleServiceRegisterResult, this));
    AddServiceRegistration(std::make_shared<DnssdServiceRegistration>(aHostName, aName, aType, sortedSubTypeList, aPort,
                                                                      sortedTxtList, std::move(aCallback), serviceRef));

exit:
    if (error != kDNSServiceErr_NoError || ret != OTBR_ERROR_NONE)
    {
        if (error != kDNSServiceErr_NoError)
        {
            ret = DNSErrorToOtbrError(error);
            otbrLogErr("Failed to publish service %s.%s for mdnssd error: %s!", aName.c_str(), aType.c_str(),
                       DNSErrorToString(error));
        }

        if (serviceRef != nullptr)
        {
            DNSServiceRefDeallocate(serviceRef);
        }
        std::move(aCallback)(ret);
    }
}

void PublisherMDnsSd::UnpublishService(const std::string &aName, const std::string &aType, ResultCallback &&aCallback)
{
    RemoveServiceRegistration(aName, aType);
    std::move(aCallback)(OTBR_ERROR_NONE);
}

void PublisherMDnsSd::PublishHost(const std::string &         aName,
                                  const std::vector<uint8_t> &aAddress,
                                  ResultCallback &&           aCallback)
{
    otbrError    ret   = OTBR_ERROR_NONE;
    int          error = 0;
    std::string  fullName;
    DNSRecordRef recordRef = nullptr;

    // Supports only IPv6 for now, may support IPv4 in the future.
    VerifyOrExit(aAddress.size() == OTBR_IP6_ADDRESS_SIZE, error = OTBR_ERROR_INVALID_ARGS);

    fullName = MakeFullHostName(aName);

    if (mHostsRef == nullptr)
    {
        SuccessOrExit(error = DNSServiceCreateConnection(&mHostsRef));
    }

    aCallback = HandleDuplicateHostRegistration(aName, aAddress, std::move(aCallback));
    if (aCallback.IsNull())
    {
        ExitNow();
    }

    otbrLogInfo("Publish new host %s", aName.c_str());
    SuccessOrExit(error = DNSServiceRegisterRecord(mHostsRef, &recordRef, kDNSServiceFlagsUnique,
                                                   kDNSServiceInterfaceIndexAny, fullName.c_str(), kDNSServiceType_AAAA,
                                                   kDNSServiceClass_IN, aAddress.size(), aAddress.data(), /* ttl */ 0,
                                                   HandleRegisterHostResult, this));
    AddHostRegistration(
        std::make_shared<DnssdHostRegistration>(aName, aAddress, std::move(aCallback), mHostsRef, recordRef));

exit:
    if (error != kDNSServiceErr_NoError || ret != OTBR_ERROR_NONE)
    {
        if (error != kDNSServiceErr_NoError)
        {
            ret = DNSErrorToOtbrError(error);
            otbrLogErr("Failed to publish/update host %s for mdnssd error: %s!", aName.c_str(),
                       DNSErrorToString(error));
        }

        std::move(aCallback)(ret);
    }
}

void PublisherMDnsSd::UnpublishHost(const std::string &aName, ResultCallback &&aCallback)
{
    otbrLogInfo("Removing host %s", MakeFullHostName(aName).c_str());

    RemoveHostRegistration(aName);

    // We may failed to unregister the host from underlying mDNS publishers, but
    // it usually means that the mDNS publisher is already not functioning. So it's
    // okay to return success directly since the service is not advertised anyway.
    std::move(aCallback)(OTBR_ERROR_NONE);
}

void PublisherMDnsSd::HandleRegisterHostResult(DNSServiceRef       aServiceRef,
                                               DNSRecordRef        aRecordRef,
                                               DNSServiceFlags     aFlags,
                                               DNSServiceErrorType aError,
                                               void *              aContext)
{
    static_cast<PublisherMDnsSd *>(aContext)->HandleRegisterHostResult(aServiceRef, aRecordRef, aFlags, aError);
}

void PublisherMDnsSd::HandleRegisterHostResult(DNSServiceRef       aServiceRef,
                                               DNSRecordRef        aRecordRef,
                                               DNSServiceFlags     aFlags,
                                               DNSServiceErrorType aError)
{
    OTBR_UNUSED_VARIABLE(aFlags);

    otbrError           error   = DNSErrorToOtbrError(aError);
    HostRegistrationPtr hostReg = FindHostRegistration(aServiceRef, aRecordRef);

    std::string hostName;

    VerifyOrExit(hostReg != nullptr);

    hostName = MakeFullHostName(hostReg->mName);

    otbrLogInfo("Received reply for host %s", hostName.c_str());

    if (error == OTBR_ERROR_NONE)
    {
        otbrLogInfo("Successfully registered host %s", hostName.c_str());
        hostReg->Complete(OTBR_ERROR_NONE);
    }
    else
    {
        otbrLogWarning("failed to register host %s for mdnssd error: %s", hostName.c_str(), DNSErrorToString(aError));
        hostReg->Complete(error);
        RemoveHostRegistration(hostReg->mName);
    }

exit:
    return;
}

// See `regtype` parameter of the DNSServiceRegister() function for more information.
std::string PublisherMDnsSd::MakeRegType(const std::string &aType, SubTypeList aSubTypeList)
{
    std::string regType = aType;

    std::sort(aSubTypeList.begin(), aSubTypeList.end());

    for (const auto &subType : aSubTypeList)
    {
        regType += "," + subType;
    }

    return regType;
}

void PublisherMDnsSd::SubscribeService(const std::string &aType, const std::string &aInstanceName)
{
    mSubscribedServices.emplace_back(*this, aType, aInstanceName);

    otbrLogInfo("subscribe service %s.%s (total %zu)", aInstanceName.c_str(), aType.c_str(),
                mSubscribedServices.size());

    if (aInstanceName.empty())
    {
        mSubscribedServices.back().Browse();
    }
    else
    {
        mSubscribedServices.back().Resolve(kDNSServiceInterfaceIndexAny, aInstanceName, aType, kDomain);
    }
}

void PublisherMDnsSd::UnsubscribeService(const std::string &aType, const std::string &aInstanceName)
{
    ServiceSubscriptionList::iterator it =
        std::find_if(mSubscribedServices.begin(), mSubscribedServices.end(),
                     [&aType, &aInstanceName](const ServiceSubscription &aService) {
                         return aService.mType == aType && aService.mInstanceName == aInstanceName;
                     });

    assert(it != mSubscribedServices.end());

    it->Release();
    mSubscribedServices.erase(it);

    otbrLogInfo("unsubscribe service %s.%s (left %zu)", aInstanceName.c_str(), aType.c_str(),
                mSubscribedServices.size());
}

void PublisherMDnsSd::OnServiceResolved(PublisherMDnsSd::ServiceSubscription &aService)
{
    otbrLogInfo("Service %s is resolved successfully: %s host %s addresses %zu", aService.mType.c_str(),
                aService.mInstanceInfo.mName.c_str(), aService.mInstanceInfo.mHostName.c_str(),
                aService.mInstanceInfo.mAddresses.size());

    if (mDiscoveredServiceInstanceCallback != nullptr)
    {
        mDiscoveredServiceInstanceCallback(aService.mType, aService.mInstanceInfo);
    }
}

void PublisherMDnsSd::OnServiceResolveFailed(const ServiceSubscription &aService, DNSServiceErrorType aErrorCode)
{
    otbrLogWarning("Service %s resolving failed: code=%d", aService.mType.c_str(), aErrorCode);
}

void PublisherMDnsSd::OnHostResolved(PublisherMDnsSd::HostSubscription &aHost)
{
    otbrLogInfo("Host %s is resolved successfully: host %s addresses %zu ttl %u", aHost.mHostName.c_str(),
                aHost.mHostInfo.mHostName.c_str(), aHost.mHostInfo.mAddresses.size(), aHost.mHostInfo.mTtl);

    if (mDiscoveredHostCallback != nullptr)
    {
        mDiscoveredHostCallback(aHost.mHostName, aHost.mHostInfo);
    }
}

void PublisherMDnsSd::OnHostResolveFailed(const PublisherMDnsSd::HostSubscription &aHost,
                                          DNSServiceErrorType                      aErrorCode)
{
    otbrLogWarning("Host %s resolving failed: code=%d", aHost.mHostName.c_str(), aErrorCode);
}

void PublisherMDnsSd::SubscribeHost(const std::string &aHostName)
{
    mSubscribedHosts.emplace_back(*this, aHostName);

    otbrLogInfo("subscribe host %s (total %zu)", aHostName.c_str(), mSubscribedHosts.size());

    mSubscribedHosts.back().Resolve();
}

void PublisherMDnsSd::UnsubscribeHost(const std::string &aHostName)
{
    HostSubscriptionList ::iterator it =
        std::find_if(mSubscribedHosts.begin(), mSubscribedHosts.end(),
                     [&aHostName](const HostSubscription &aHost) { return aHost.mHostName == aHostName; });

    assert(it != mSubscribedHosts.end());

    it->Release();
    mSubscribedHosts.erase(it);

    otbrLogInfo("unsubscribe host %s (remaining %d)", aHostName.c_str(), mSubscribedHosts.size());
}

Publisher *Publisher::Create(StateCallback aCallback)
{
    return new PublisherMDnsSd(aCallback);
}

void Publisher::Destroy(Publisher *aPublisher)
{
    delete static_cast<PublisherMDnsSd *>(aPublisher);
}

void PublisherMDnsSd::Subscription::Release(void)
{
    DeallocateServiceRef();
}

void PublisherMDnsSd::Subscription::DeallocateServiceRef(void)
{
    if (mServiceRef != nullptr)
    {
        DNSServiceRefDeallocate(mServiceRef);
        mServiceRef = nullptr;
    }
}

void PublisherMDnsSd::ServiceSubscription::Browse(void)
{
    assert(mServiceRef == nullptr);

    otbrLogInfo("DNSServiceBrowse %s", mType.c_str());
    DNSServiceBrowse(&mServiceRef, /* flags */ kDNSServiceFlagsTimeout, kDNSServiceInterfaceIndexAny, mType.c_str(),
                     /* domain */ nullptr, HandleBrowseResult, this);
}

void PublisherMDnsSd::ServiceSubscription::HandleBrowseResult(DNSServiceRef       aServiceRef,
                                                              DNSServiceFlags     aFlags,
                                                              uint32_t            aInterfaceIndex,
                                                              DNSServiceErrorType aErrorCode,
                                                              const char *        aInstanceName,
                                                              const char *        aType,
                                                              const char *        aDomain,
                                                              void *              aContext)
{
    static_cast<ServiceSubscription *>(aContext)->HandleBrowseResult(aServiceRef, aFlags, aInterfaceIndex, aErrorCode,
                                                                     aInstanceName, aType, aDomain);
}

void PublisherMDnsSd::ServiceSubscription::HandleBrowseResult(DNSServiceRef       aServiceRef,
                                                              DNSServiceFlags     aFlags,
                                                              uint32_t            aInterfaceIndex,
                                                              DNSServiceErrorType aErrorCode,
                                                              const char *        aInstanceName,
                                                              const char *        aType,
                                                              const char *        aDomain)
{
    OTBR_UNUSED_VARIABLE(aServiceRef);
    OTBR_UNUSED_VARIABLE(aDomain);

    otbrLogInfo("DNSServiceBrowse reply: %s.%s inf %u, flags=%u, error=%d", aInstanceName, aType, aInterfaceIndex,
                aFlags, aErrorCode);

    VerifyOrExit(aErrorCode == kDNSServiceErr_NoError);
    VerifyOrExit(aFlags & kDNSServiceFlagsAdd);

    DeallocateServiceRef();
    Resolve(aInterfaceIndex, aInstanceName, aType, aDomain);

exit:
    if (aErrorCode != kDNSServiceErr_NoError)
    {
        mMDnsSd->OnServiceResolveFailed(*this, aErrorCode);
    }
    else if (!(aFlags & (kDNSServiceFlagsAdd | kDNSServiceFlagsMoreComing)))
    {
        mMDnsSd->OnServiceResolveFailed(*this, kDNSServiceErr_NoSuchName);
    }
}

void PublisherMDnsSd::ServiceSubscription::Resolve(uint32_t           aInterfaceIndex,
                                                   const std::string &aInstanceName,
                                                   const std::string &aType,
                                                   const std::string &aDomain)
{
    assert(mServiceRef == nullptr);

    otbrLogInfo("DNSServiceResolve %s %s inf %d", aInstanceName.c_str(), aType.c_str(), aInterfaceIndex);
    DNSServiceResolve(&mServiceRef, /* flags */ 0, aInterfaceIndex, aInstanceName.c_str(), aType.c_str(),
                      aDomain.c_str(), HandleResolveResult, this);
}

void PublisherMDnsSd::ServiceSubscription::HandleResolveResult(DNSServiceRef        aServiceRef,
                                                               DNSServiceFlags      aFlags,
                                                               uint32_t             aInterfaceIndex,
                                                               DNSServiceErrorType  aErrorCode,
                                                               const char *         aFullName,
                                                               const char *         aHostTarget,
                                                               uint16_t             aPort,
                                                               uint16_t             aTxtLen,
                                                               const unsigned char *aTxtRecord,
                                                               void *               aContext)
{
    static_cast<ServiceSubscription *>(aContext)->HandleResolveResult(
        aServiceRef, aFlags, aInterfaceIndex, aErrorCode, aFullName, aHostTarget, aPort, aTxtLen, aTxtRecord);
}

void PublisherMDnsSd::ServiceSubscription::HandleResolveResult(DNSServiceRef        aServiceRef,
                                                               DNSServiceFlags      aFlags,
                                                               uint32_t             aInterfaceIndex,
                                                               DNSServiceErrorType  aErrorCode,
                                                               const char *         aFullName,
                                                               const char *         aHostTarget,
                                                               uint16_t             aPort,
                                                               uint16_t             aTxtLen,
                                                               const unsigned char *aTxtRecord)
{
    OTBR_UNUSED_VARIABLE(aServiceRef);

    std::string instanceName, type, domain;
    otbrError   error = OTBR_ERROR_NONE;

    otbrLogInfo("DNSServiceResolve reply: %s host %s:%d, TXT=%dB inf %u, flags=%u", aFullName, aHostTarget, aPort,
                aTxtLen, aInterfaceIndex, aFlags);

    VerifyOrExit(aErrorCode == kDNSServiceErr_NoError);

    SuccessOrExit(error = SplitFullServiceInstanceName(aFullName, instanceName, type, domain));

    mInstanceInfo.mName     = instanceName;
    mInstanceInfo.mHostName = aHostTarget;
    mInstanceInfo.mPort     = ntohs(aPort);
    mInstanceInfo.mTxtData.assign(aTxtRecord, aTxtRecord + aTxtLen);
    // priority and weight are not given in the reply
    mInstanceInfo.mPriority = 0;
    mInstanceInfo.mWeight   = 0;

    DeallocateServiceRef();
    GetAddrInfo(aInterfaceIndex);

exit:
    if (aErrorCode != kDNSServiceErr_NoError || error != OTBR_ERROR_NONE)
    {
        mMDnsSd->OnServiceResolveFailed(*this, aErrorCode);
    }

    if (error != OTBR_ERROR_NONE)
    {
        otbrLogWarning("failed to resolve service instance %s", aFullName);
    }
}

void PublisherMDnsSd::ServiceSubscription::GetAddrInfo(uint32_t aInterfaceIndex)
{
    assert(mServiceRef == nullptr);

    otbrLogInfo("DNSServiceGetAddrInfo %s inf %d", mInstanceInfo.mHostName.c_str(), aInterfaceIndex);

    DNSServiceGetAddrInfo(&mServiceRef, /* flags */ 0, aInterfaceIndex,
                          kDNSServiceProtocol_IPv6 | kDNSServiceProtocol_IPv4, mInstanceInfo.mHostName.c_str(),
                          HandleGetAddrInfoResult, this);
}

void PublisherMDnsSd::ServiceSubscription::HandleGetAddrInfoResult(DNSServiceRef          aServiceRef,
                                                                   DNSServiceFlags        aFlags,
                                                                   uint32_t               aInterfaceIndex,
                                                                   DNSServiceErrorType    aErrorCode,
                                                                   const char *           aHostName,
                                                                   const struct sockaddr *aAddress,
                                                                   uint32_t               aTtl,
                                                                   void *                 aContext)
{
    static_cast<ServiceSubscription *>(aContext)->HandleGetAddrInfoResult(aServiceRef, aFlags, aInterfaceIndex,
                                                                          aErrorCode, aHostName, aAddress, aTtl);
}

void PublisherMDnsSd::ServiceSubscription::HandleGetAddrInfoResult(DNSServiceRef          aServiceRef,
                                                                   DNSServiceFlags        aFlags,
                                                                   uint32_t               aInterfaceIndex,
                                                                   DNSServiceErrorType    aErrorCode,
                                                                   const char *           aHostName,
                                                                   const struct sockaddr *aAddress,
                                                                   uint32_t               aTtl)
{
    OTBR_UNUSED_VARIABLE(aServiceRef);
    OTBR_UNUSED_VARIABLE(aInterfaceIndex);

    Ip6Address address;

    otbrLogDebug("DNSServiceGetAddrInfo reply: %d, flags=%u, host=%s, sa_family=%d", aErrorCode, aFlags, aHostName,
                 aAddress->sa_family);

    VerifyOrExit(aErrorCode == kDNSServiceErr_NoError);
    VerifyOrExit((aFlags & kDNSServiceFlagsAdd) && aAddress->sa_family == AF_INET6);

    address.CopyFrom(*reinterpret_cast<const struct sockaddr_in6 *>(aAddress));
    VerifyOrExit(!address.IsUnspecified() && !address.IsLinkLocal() && !address.IsMulticast() && !address.IsLoopback(),
                 otbrLogDebug("DNSServiceGetAddrInfo ignores address %s", address.ToString().c_str()));

    mInstanceInfo.mAddresses.push_back(address);
    mInstanceInfo.mTtl = aTtl;

    otbrLogDebug("DNSServiceGetAddrInfo reply: address=%s, ttl=%u", address.ToString().c_str(), aTtl);

    mMDnsSd->OnServiceResolved(*this);

exit:
    if (aErrorCode != kDNSServiceErr_NoError)
    {
        otbrLogWarning("DNSServiceGetAddrInfo failed: %d", aErrorCode);

        mMDnsSd->OnServiceResolveFailed(*this, aErrorCode);
    }
    else if (mInstanceInfo.mAddresses.empty() && (aFlags & kDNSServiceFlagsMoreComing) == 0)
    {
        otbrLogDebug("DNSServiceGetAddrInfo reply: no IPv6 address found");
        mInstanceInfo.mTtl = aTtl;
        mMDnsSd->OnServiceResolved(*this);
    }
}

void PublisherMDnsSd::HostSubscription::Resolve(void)
{
    std::string fullHostName = MakeFullHostName(mHostName);

    assert(mServiceRef == nullptr);

    otbrLogDebug("DNSServiceGetAddrInfo %s inf %d", fullHostName.c_str(), kDNSServiceInterfaceIndexAny);

    DNSServiceGetAddrInfo(&mServiceRef, /* flags */ 0, kDNSServiceInterfaceIndexAny,
                          kDNSServiceProtocol_IPv6 | kDNSServiceProtocol_IPv4, fullHostName.c_str(),
                          HandleResolveResult, this);
}

void PublisherMDnsSd::HostSubscription::HandleResolveResult(DNSServiceRef          aServiceRef,
                                                            DNSServiceFlags        aFlags,
                                                            uint32_t               aInterfaceIndex,
                                                            DNSServiceErrorType    aErrorCode,
                                                            const char *           aHostName,
                                                            const struct sockaddr *aAddress,
                                                            uint32_t               aTtl,
                                                            void *                 aContext)
{
    static_cast<HostSubscription *>(aContext)->HandleResolveResult(aServiceRef, aFlags, aInterfaceIndex, aErrorCode,
                                                                   aHostName, aAddress, aTtl);
}

void PublisherMDnsSd::HostSubscription::HandleResolveResult(DNSServiceRef          aServiceRef,
                                                            DNSServiceFlags        aFlags,
                                                            uint32_t               aInterfaceIndex,
                                                            DNSServiceErrorType    aErrorCode,
                                                            const char *           aHostName,
                                                            const struct sockaddr *aAddress,
                                                            uint32_t               aTtl)
{
    OTBR_UNUSED_VARIABLE(aServiceRef);
    OTBR_UNUSED_VARIABLE(aInterfaceIndex);

    Ip6Address address;

    otbrLogDebug("DNSServiceGetAddrInfo reply: %d, flags=%u, host=%s, sa_family=%d", aErrorCode, aFlags, aHostName,
                 aAddress->sa_family);

    VerifyOrExit(aErrorCode == kDNSServiceErr_NoError);
    VerifyOrExit((aFlags & kDNSServiceFlagsAdd) && aAddress->sa_family == AF_INET6);

    address.CopyFrom(*reinterpret_cast<const struct sockaddr_in6 *>(aAddress));
    VerifyOrExit(!address.IsLinkLocal(),
                 otbrLogDebug("DNSServiceGetAddrInfo ignore link-local address %s", address.ToString().c_str()));

    mHostInfo.mHostName = aHostName;
    mHostInfo.mAddresses.push_back(address);
    mHostInfo.mTtl = aTtl;

    otbrLogDebug("DNSServiceGetAddrInfo reply: address=%s, ttl=%u", address.ToString().c_str(), aTtl);

    mMDnsSd->OnHostResolved(*this);

exit:
    if (aErrorCode != kDNSServiceErr_NoError)
    {
        otbrLogWarning("DNSServiceGetAddrInfo failed: %d", aErrorCode);

        mMDnsSd->OnHostResolveFailed(*this, aErrorCode);
    }
    else if (mHostInfo.mAddresses.empty() && (aFlags & kDNSServiceFlagsMoreComing) == 0)
    {
        otbrLogDebug("DNSServiceGetAddrInfo reply: no IPv6 address found");
        mHostInfo.mTtl = aTtl;
        mMDnsSd->OnHostResolved(*this);
    }
}

} // namespace Mdns

} // namespace otbr

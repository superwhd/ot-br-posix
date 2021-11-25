/*
 *    Copyright (c) 2021, The OpenThread Authors.
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
 *   This file includes implementation of mDNS publisher.
 */

#include "mdns/mdns.hpp"

#include <assert.h>

#include <algorithm>
#include <functional>

#include "common/code_utils.hpp"

namespace otbr {

namespace Mdns {

bool Publisher::IsServiceTypeEqual(std::string aFirstType, std::string aSecondType)
{
    if (!aFirstType.empty() && aFirstType.back() == '.')
    {
        aFirstType.pop_back();
    }

    if (!aSecondType.empty() && aSecondType.back() == '.')
    {
        aSecondType.pop_back();
    }

    return aFirstType == aSecondType;
}

otbrError Publisher::EncodeTxtData(TxtList aTxtList, std::vector<uint8_t> &aTxtData)
{
    otbrError error = OTBR_ERROR_NONE;

    for (const auto &txtEntry : aTxtList)
    {
        const auto & name        = txtEntry.mName;
        const auto & value       = txtEntry.mValue;
        const size_t entryLength = name.length() + 1 + value.size();

        VerifyOrExit(entryLength <= kMaxTextEntrySize, error = OTBR_ERROR_INVALID_ARGS);

        aTxtData.push_back(static_cast<uint8_t>(entryLength));
        aTxtData.insert(aTxtData.end(), name.begin(), name.end());
        aTxtData.push_back('=');
        aTxtData.insert(aTxtData.end(), value.begin(), value.end());
    }

exit:
    return error;
}

Publisher::SubTypeList Publisher::SortSubTypeList(SubTypeList aSubTypeList)
{
    std::sort(aSubTypeList.begin(), aSubTypeList.end());
    return aSubTypeList;
}

Publisher::TxtList Publisher::SortTxtList(TxtList aTxtList)
{
    std::sort(aTxtList.begin(), aTxtList.end(),
              [](const TxtEntry &aLhs, const TxtEntry &aRhs) { return aLhs.mName < aRhs.mName; });
    return aTxtList;
}

std::string Publisher::MakeFullServiceName(const std::string &aName, const std::string &aType)
{
    return aName + "." + aType + ".local";
}

std::string Publisher::MakeFullHostName(const std::string &aName)
{
    return aName + ".local";
}

void Publisher::AddServiceRegistration(ServiceRegistrationPtr aServiceReg)
{
    mServiceRegistrations[MakeFullServiceName(aServiceReg->mName, aServiceReg->mType)] = aServiceReg;
}

void Publisher::RemoveServiceRegistration(const std::string &aName, const std::string &aType)
{
    otbrLogInfo("Removing service %s.%s", aName.c_str(), aType.c_str());
    mServiceRegistrations.erase(MakeFullServiceName(aName, aType));
}

Publisher::ServiceRegistrationPtr Publisher::FindServiceRegistration(const std::string &aName, const std::string &aType)
{
    return mServiceRegistrations[MakeFullServiceName(aName, aType)];
}

Publisher::ResultCallback Publisher::HandleDuplicateServiceRegistration(const std::string &aHostName,
                                                                        const std::string &aName,
                                                                        const std::string &aType,
                                                                        const SubTypeList &aSubTypeList,
                                                                        uint16_t           aPort,
                                                                        const TxtList &    aTxtList,
                                                                        ResultCallback &&  aCallback)
{
    ServiceRegistrationPtr serviceReg = FindServiceRegistration(aName, aType);

    VerifyOrExit(serviceReg != nullptr);

    if (serviceReg->IsOutdated(aHostName, aName, aType, aSubTypeList, aPort, aTxtList))
    {
        RemoveServiceRegistration(aName, aType);
    }
    else if (serviceReg->IsCompleted())
    {
        // Returns success if the same service has already been
        // registered with exactly the same parameters.
        std::move(aCallback)(OTBR_ERROR_NONE);
    }
    else
    {
        // If the same service is being registered with the same parameters,
        // let's join the waiting queue for the result.
        serviceReg->mCallback = std::bind(
            [](std::shared_ptr<ResultCallback> aExistingCallback, std::shared_ptr<ResultCallback> aNewCallback,
               otbrError aError) {
                std::move (*aExistingCallback)(aError);
                std::move (*aNewCallback)(aError);
            },
            std::make_shared<ResultCallback>(std::move(serviceReg->mCallback)),
            std::make_shared<ResultCallback>(std::move(aCallback)), std::placeholders::_1);
    }

exit:
    return std::move(aCallback);
}

Publisher::ResultCallback Publisher::HandleDuplicateHostRegistration(const std::string &         aName,
                                                                     const std::vector<uint8_t> &aAddress,
                                                                     ResultCallback &&           aCallback)
{
    HostRegistrationPtr hostReg = FindHostRegistration(aName);

    VerifyOrExit(hostReg != nullptr);

    if (hostReg->IsOutdated(aName, aAddress))
    {
        RemoveHostRegistration(hostReg->mName);
    }
    else if (hostReg->IsCompleted())
    {
        // Returns success if the same service has already been
        // registered with exactly the same parameters.
        std::move(aCallback)(OTBR_ERROR_NONE);
    }
    else
    {
        // If the same service is being registered with the same parameters,
        // let's join the waiting queue for the result.
        hostReg->mCallback = std::bind(
            [](std::shared_ptr<ResultCallback> aExistingCallback, std::shared_ptr<ResultCallback> aNewCallback,
               otbrError aError) {
                std::move (*aExistingCallback)(aError);
                std::move (*aNewCallback)(aError);
            },
            std::make_shared<ResultCallback>(std::move(hostReg->mCallback)),
            std::make_shared<ResultCallback>(std::move(aCallback)), std::placeholders::_1);
    }

exit:
    return std::move(aCallback);
}

void Publisher::AddHostRegistration(HostRegistrationPtr aHostReg)
{
    mHostRegistrations[MakeFullHostName(aHostReg->mName)] = aHostReg;
}

void Publisher::RemoveHostRegistration(const std::string &aName)
{
    mHostRegistrations.erase(MakeFullHostName(aName));
}

Publisher::HostRegistrationPtr Publisher::FindHostRegistration(const std::string &aName)
{
    return mHostRegistrations[MakeFullHostName(aName)];
}

Publisher::Registration::~Registration(void)
{
    if (!mCallback.IsNull())
    {
        std::move(mCallback)(OTBR_ERROR_ABORTED);
    }
}

bool Publisher::ServiceRegistration::IsOutdated(const std::string &aHostName,
                                                const std::string &aName,
                                                const std::string &aType,
                                                const SubTypeList &aSubTypeList,
                                                uint16_t           aPort,
                                                const TxtList &    aTxtList) const
{
    return !(mHostName == aHostName && mName == aName && mType == aType && mSubTypeList == aSubTypeList &&
             mPort == aPort && mTxtList == aTxtList);
}

bool Publisher::HostRegistration::IsOutdated(const std::string &aName, const std::vector<uint8_t> &aAddress) const
{
    return !(mName == aName && mAddress == aAddress);
}

} // namespace Mdns

} // namespace otbr

#include "openthread/platform/srp_replication.h"

#include <random>
#include <sstream>
#include "mdns/mdns.hpp"
#include "openthread/ip6.h"
#include "openthread/openthread-system.h"
#include "openthread/thread.h"

static constexpr const char *kSrplServiceInstanceName = "srpl";
static constexpr const char *kSrplServiceType         = "_srpl-tls._tcp";
static const uint16_t        kSrplPort                = otPlatSrplPort();

namespace {

std::string GenerateServiceInstanceName();

bool        sBrowseEnabled           = false;
std::string sSrplServiceInstanceName = GenerateServiceInstanceName();

void UnpublishSrplService()
{
    otbrLogInfo("Unpublishing SRPL service: %s", sSrplServiceInstanceName.c_str());
    otbr::Mdns::Publisher::GetInstance().UnpublishService(
        sSrplServiceInstanceName, kSrplServiceType, [](otbrError aError) {
            otbrLogResult(aError, "Result of unpublish SRPL service %s.%s.local", sSrplServiceInstanceName.c_str(),
                          kSrplServiceType);
        });
}

void PublishSrplService(const otbr::Mdns::Publisher::TxtList &aTxtList)
{
    otbr::Mdns::Publisher::GetInstance().PublishService(
        "", sSrplServiceInstanceName, kSrplServiceType, {}, kSrplPort, aTxtList, [aTxtList](otbrError aError) {
            if (aError == OTBR_ERROR_DUPLICATED)
            {
                otbrLogCrit("failed to publish SRPL service %s due to name conflict. Renaming",
                            sSrplServiceInstanceName.c_str());
                UnpublishSrplService();
                sSrplServiceInstanceName = GenerateServiceInstanceName();
                PublishSrplService(aTxtList);
            }
            else
            {
                otbrLogResult(aError, "Publish SRPL service %s", sSrplServiceInstanceName.c_str());
            }
        });
}

std::string GenerateServiceInstanceName()
{
    std::random_device                      r;
    std::default_random_engine              engine(r());
    std::uniform_int_distribution<uint16_t> uniform_dist(1, 0xFFFF);
    uint16_t                                rand = uniform_dist(engine);
    std::stringstream                       ss;

    ss << kSrplServiceInstanceName << "(" << rand << ")";
    return ss.str();
}

void HandleDiscoveredPeerInfo(otInstance *                                         aInstance,
                              const std::string &                                  aType,
                              const otbr::Mdns::Publisher::DiscoveredInstanceInfo &aInstanceInfo)
{
    if (aType == "_srpl-tls._tcp")
    {
        otPlatSrplPartnerInfo partnerInfo;
        partnerInfo.mRemoved = aInstanceInfo.mRemoved;
        otbrLogInfo("discovered SRPL peer: %s", aInstanceInfo.mName.c_str());
        if (aInstanceInfo.mNetifIndex != otSysGetInfraNetifIndex())
        {
            return;
        }
        if (!partnerInfo.mRemoved)
        {
            partnerInfo.mTxtData   = aInstanceInfo.mTxtData.data();
            partnerInfo.mTxtLength = aInstanceInfo.mTxtData.size();
            if (aInstanceInfo.mAddresses.empty())
            {
                return;
            }
            otbrLogInfo("addr: %s %d", aInstanceInfo.mAddresses.front().ToString().c_str(), aInstanceInfo.mPort);
            SuccessOrDie(otIp6AddressFromString(aInstanceInfo.mAddresses.front().ToString().c_str(),
                                                &partnerInfo.mSockAddr.mAddress),
                         "failed to parse address");
            partnerInfo.mSockAddr.mPort = aInstanceInfo.mPort;
        }
        // TODO: skip itself
        bool isSelf = false;
        // TODO: check address to determine if it's itself?
        if (aInstanceInfo.mName == sSrplServiceInstanceName)
        {
            isSelf = true;
        }
        otbrLogInfo("%s == %s ? %d", aInstanceInfo.mName.c_str(), sSrplServiceInstanceName.c_str(), isSelf);
        if (!isSelf)
        {
            if (!partnerInfo.mRemoved)
            {
                otbrLogInfo("Handle browse result %s %d ", aInstanceInfo.mAddresses.front().ToString().c_str(),
                            aInstanceInfo.mPort);
            }
            otPlatSrplHandleDnssdBrowseResult(aInstance, &partnerInfo);
        }
    }
}
} // namespace

extern "C" void otPlatSrplRegisterDnssdService(otInstance *aInstance, const uint8_t *aTxtData, uint16_t aTxtLength)
{
    OTBR_UNUSED_VARIABLE(aInstance);
    otbrLogWarning("!!!! otPlatSrplRegisterDnssdService atxtlength = %d", aTxtLength);
    otbr::Mdns::Publisher::TxtList txtList;
    otbr::Mdns::Publisher::DecodeTxtData(txtList, aTxtData, aTxtLength);
    PublishSrplService(txtList);
}

extern "C" void otPlatSrplUnregisterDnssdService(otInstance *aInstance)
{
    OTBR_UNUSED_VARIABLE(aInstance);
    otbr::Mdns::Publisher::GetInstance().UnpublishService(sSrplServiceInstanceName, kSrplServiceType,
                                                          [](otbrError aError) { OT_UNUSED_VARIABLE(aError); });
}

extern "C" void otPlatSrplDnssdBrowse(otInstance *aInstance, bool aEnable)
{
    static uint64_t sSubscriberId = 0;
    OTBR_UNUSED_VARIABLE(aInstance);
    VerifyOrExit(aEnable != sBrowseEnabled);
    sBrowseEnabled = aEnable;
    if (sBrowseEnabled)
    {
        VerifyOrExit(!sSubscriberId);
        sSubscriberId = otbr::Mdns::Publisher::GetInstance().AddSubscriptionCallbacks(
            [aInstance](const std::string &aType, const otbr::Mdns::Publisher::DiscoveredInstanceInfo &aInstanceInfo) {
                HandleDiscoveredPeerInfo(aInstance, aType, aInstanceInfo);
            },
            nullptr);
        otbr::Mdns::Publisher::GetInstance().SubscribeService(kSrplServiceType, "");
    }
    else
    {
        VerifyOrExit(sSubscriberId);
        otbr::Mdns::Publisher::GetInstance().UnsubscribeService(kSrplServiceType, "");
        otbr::Mdns::Publisher::GetInstance().RemoveSubscriptionCallbacks(sSubscriberId);
        sSubscriberId = 0;
    }
    OT_UNUSED_VARIABLE(sSubscriberId);
exit:
    return;
}

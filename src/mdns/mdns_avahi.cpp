/*
 *    Copyright (c) 2017, The OpenThread Authors.
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
 *   This file implements mDNS publisher based on avahi.
 */

#define OTBR_LOG_TAG "MDNS"

#include "mdns/mdns_avahi.hpp"

#include <algorithm>

#include <avahi-client/client.h>
#include <avahi-common/alternative.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/timeval.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "common/code_utils.hpp"
#include "common/logging.hpp"
#include "common/time.hpp"
#include "utils/strcpy_utils.hpp"

struct AvahiWatch
{
    int                mFd;       ///< The file descriptor to watch.
    AvahiWatchEvent    mEvents;   ///< The interested events.
    int                mHappened; ///< The events happened.
    AvahiWatchCallback mCallback; ///< The function to be called when interested events happened on mFd.
    void *             mContext;  ///< A pointer to application-specific context.
    void *             mPoller;   ///< The poller created this watch.

    /**
     * The constructor to initialize an Avahi watch.
     *
     * @param[in] aFd        The file descriptor to watch.
     * @param[in] aEvents    The events to watch.
     * @param[in] aCallback  The function to be called when events happend on this file descriptor.
     * @param[in] aContext   A pointer to application-specific context.
     * @param[in] aPoller    The AvahiPoller this watcher belongs to.
     *
     */
    AvahiWatch(int aFd, AvahiWatchEvent aEvents, AvahiWatchCallback aCallback, void *aContext, void *aPoller)
        : mFd(aFd)
        , mEvents(aEvents)
        , mCallback(aCallback)
        , mContext(aContext)
        , mPoller(aPoller)
    {
    }
};

/**
 * This structure implements the AvahiTimeout.
 *
 */
struct AvahiTimeout
{
    otbr::Timepoint      mTimeout;  ///< Absolute time when this timer timeout.
    AvahiTimeoutCallback mCallback; ///< The function to be called when timeout.
    void *               mContext;  ///< The pointer to application-specific context.
    void *               mPoller;   ///< The poller created this timer.

    /**
     * The constructor to initialize an AvahiTimeout.
     *
     * @param[in] aTimeout   A pointer to the time after which the callback should be called.
     * @param[in] aCallback  The function to be called after timeout.
     * @param[in] aContext   A pointer to application-specific context.
     * @param[in] aPoller    The AvahiPoller this timeout belongs to.
     *
     */
    AvahiTimeout(const struct timeval *aTimeout, AvahiTimeoutCallback aCallback, void *aContext, void *aPoller)
        : mCallback(aCallback)
        , mContext(aContext)
        , mPoller(aPoller)
    {
        if (aTimeout)
        {
            mTimeout = otbr::Clock::now() + otbr::FromTimeval<otbr::Microseconds>(*aTimeout);
        }
        else
        {
            mTimeout = otbr::Timepoint::min();
        }
    }
};

namespace otbr {

namespace Mdns {

class AvahiPoller : public MainloopProcessor
{
public:
    AvahiPoller(void);

    // Implementation of MainloopProcessor.

    void Update(MainloopContext &aMainloop) override;
    void Process(const MainloopContext &aMainloop) override;

    const AvahiPoll *GetAvahiPoll(void) const { return &mAvahiPoller; }

private:
    typedef std::vector<AvahiWatch *>   Watches;
    typedef std::vector<AvahiTimeout *> Timers;

    static AvahiWatch *    WatchNew(const struct AvahiPoll *aPoller,
                                    int                     aFd,
                                    AvahiWatchEvent         aEvent,
                                    AvahiWatchCallback      aCallback,
                                    void *                  aContext);
    AvahiWatch *           WatchNew(int aFd, AvahiWatchEvent aEvent, AvahiWatchCallback aCallback, void *aContext);
    static void            WatchUpdate(AvahiWatch *aWatch, AvahiWatchEvent aEvent);
    static AvahiWatchEvent WatchGetEvents(AvahiWatch *aWatch);
    static void            WatchFree(AvahiWatch *aWatch);
    void                   WatchFree(AvahiWatch &aWatch);
    static AvahiTimeout *  TimeoutNew(const AvahiPoll *     aPoller,
                                      const struct timeval *aTimeout,
                                      AvahiTimeoutCallback  aCallback,
                                      void *                aContext);
    AvahiTimeout *         TimeoutNew(const struct timeval *aTimeout, AvahiTimeoutCallback aCallback, void *aContext);
    static void            TimeoutUpdate(AvahiTimeout *aTimer, const struct timeval *aTimeout);
    static void            TimeoutFree(AvahiTimeout *aTimer);
    void                   TimeoutFree(AvahiTimeout &aTimer);

    Watches   mWatches;
    Timers    mTimers;
    AvahiPoll mAvahiPoller;
};

AvahiPoller::AvahiPoller(void)
{
    mAvahiPoller.userdata         = this;
    mAvahiPoller.watch_new        = WatchNew;
    mAvahiPoller.watch_update     = WatchUpdate;
    mAvahiPoller.watch_get_events = WatchGetEvents;
    mAvahiPoller.watch_free       = WatchFree;

    mAvahiPoller.timeout_new    = TimeoutNew;
    mAvahiPoller.timeout_update = TimeoutUpdate;
    mAvahiPoller.timeout_free   = TimeoutFree;
}

AvahiWatch *AvahiPoller::WatchNew(const struct AvahiPoll *aPoller,
                                  int                     aFd,
                                  AvahiWatchEvent         aEvent,
                                  AvahiWatchCallback      aCallback,
                                  void *                  aContext)
{
    return reinterpret_cast<AvahiPoller *>(aPoller->userdata)->WatchNew(aFd, aEvent, aCallback, aContext);
}

AvahiWatch *AvahiPoller::WatchNew(int aFd, AvahiWatchEvent aEvent, AvahiWatchCallback aCallback, void *aContext)
{
    assert(aEvent && aCallback && aFd >= 0);

    mWatches.push_back(new AvahiWatch(aFd, aEvent, aCallback, aContext, this));

    return mWatches.back();
}

void AvahiPoller::WatchUpdate(AvahiWatch *aWatch, AvahiWatchEvent aEvent)
{
    aWatch->mEvents = aEvent;
}

AvahiWatchEvent AvahiPoller::WatchGetEvents(AvahiWatch *aWatch)
{
    return static_cast<AvahiWatchEvent>(aWatch->mHappened);
}

void AvahiPoller::WatchFree(AvahiWatch *aWatch)
{
    reinterpret_cast<AvahiPoller *>(aWatch->mPoller)->WatchFree(*aWatch);
}

void AvahiPoller::WatchFree(AvahiWatch &aWatch)
{
    for (Watches::iterator it = mWatches.begin(); it != mWatches.end(); ++it)
    {
        if (*it == &aWatch)
        {
            mWatches.erase(it);
            delete &aWatch;
            break;
        }
    }
}

AvahiTimeout *AvahiPoller::TimeoutNew(const AvahiPoll *     aPoller,
                                      const struct timeval *aTimeout,
                                      AvahiTimeoutCallback  aCallback,
                                      void *                aContext)
{
    assert(aPoller && aCallback);
    return static_cast<AvahiPoller *>(aPoller->userdata)->TimeoutNew(aTimeout, aCallback, aContext);
}

AvahiTimeout *AvahiPoller::TimeoutNew(const struct timeval *aTimeout, AvahiTimeoutCallback aCallback, void *aContext)
{
    mTimers.push_back(new AvahiTimeout(aTimeout, aCallback, aContext, this));
    return mTimers.back();
}

void AvahiPoller::TimeoutUpdate(AvahiTimeout *aTimer, const struct timeval *aTimeout)
{
    if (aTimeout == nullptr)
    {
        aTimer->mTimeout = Timepoint::min();
    }
    else
    {
        aTimer->mTimeout = Clock::now() + FromTimeval<Microseconds>(*aTimeout);
    }
}

void AvahiPoller::TimeoutFree(AvahiTimeout *aTimer)
{
    static_cast<AvahiPoller *>(aTimer->mPoller)->TimeoutFree(*aTimer);
}

void AvahiPoller::TimeoutFree(AvahiTimeout &aTimer)
{
    for (Timers::iterator it = mTimers.begin(); it != mTimers.end(); ++it)
    {
        if (*it == &aTimer)
        {
            mTimers.erase(it);
            delete &aTimer;
            break;
        }
    }
}

void AvahiPoller::Update(MainloopContext &aMainloop)
{
    Timepoint now = Clock::now();

    for (Watches::iterator it = mWatches.begin(); it != mWatches.end(); ++it)
    {
        int             fd     = (*it)->mFd;
        AvahiWatchEvent events = (*it)->mEvents;

        if (AVAHI_WATCH_IN & events)
        {
            FD_SET(fd, &aMainloop.mReadFdSet);
        }

        if (AVAHI_WATCH_OUT & events)
        {
            FD_SET(fd, &aMainloop.mWriteFdSet);
        }

        if (AVAHI_WATCH_ERR & events)
        {
            FD_SET(fd, &aMainloop.mErrorFdSet);
        }

        if (AVAHI_WATCH_HUP & events)
        {
            // TODO what do with this event type?
        }

        aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, fd);

        (*it)->mHappened = 0;
    }

    for (Timers::iterator it = mTimers.begin(); it != mTimers.end(); ++it)
    {
        Timepoint timeout = (*it)->mTimeout;

        if (timeout == Timepoint::min())
        {
            continue;
        }

        if (timeout <= now)
        {
            aMainloop.mTimeout = ToTimeval(Microseconds::zero());
            break;
        }
        else
        {
            auto delay = std::chrono::duration_cast<Microseconds>(timeout - now);

            if (delay < FromTimeval<Microseconds>(aMainloop.mTimeout))
            {
                aMainloop.mTimeout = ToTimeval(delay);
            }
        }
    }
}

void AvahiPoller::Process(const MainloopContext &aMainloop)
{
    Timepoint                   now = Clock::now();
    std::vector<AvahiTimeout *> expired;

    for (Watches::iterator it = mWatches.begin(); it != mWatches.end(); ++it)
    {
        int             fd     = (*it)->mFd;
        AvahiWatchEvent events = (*it)->mEvents;

        (*it)->mHappened = 0;

        if ((AVAHI_WATCH_IN & events) && FD_ISSET(fd, &aMainloop.mReadFdSet))
        {
            (*it)->mHappened |= AVAHI_WATCH_IN;
        }

        if ((AVAHI_WATCH_OUT & events) && FD_ISSET(fd, &aMainloop.mWriteFdSet))
        {
            (*it)->mHappened |= AVAHI_WATCH_OUT;
        }

        if ((AVAHI_WATCH_ERR & events) && FD_ISSET(fd, &aMainloop.mErrorFdSet))
        {
            (*it)->mHappened |= AVAHI_WATCH_ERR;
        }

        // TODO hup events
        if ((*it)->mHappened)
        {
            (*it)->mCallback(*it, (*it)->mFd, static_cast<AvahiWatchEvent>((*it)->mHappened), (*it)->mContext);
        }
    }

    for (Timers::iterator it = mTimers.begin(); it != mTimers.end(); ++it)
    {
        if ((*it)->mTimeout == Timepoint::min())
        {
            continue;
        }

        if ((*it)->mTimeout <= now)
        {
            expired.push_back(*it);
        }
    }

    for (std::vector<AvahiTimeout *>::iterator it = expired.begin(); it != expired.end(); ++it)
    {
        AvahiTimeout *avahiTimeout = *it;

        avahiTimeout->mCallback(avahiTimeout, avahiTimeout->mContext);
    }
}

PublisherAvahi::PublisherAvahi(StateCallback aStateCallback)
    : mClient(nullptr)
    , mPoller(std::unique_ptr<AvahiPoller>(new AvahiPoller()))
    , mState(State::kIdle)
    , mStateCallback(std::move(aStateCallback))
{
}

PublisherAvahi::~PublisherAvahi(void)
{
    Stop();
}

PublisherAvahi::AvahiServiceRegistration::~AvahiServiceRegistration(void)
{
    ReleaseGroup(mEntryGroup);
}

PublisherAvahi::AvahiHostRegistration::~AvahiHostRegistration(void)
{
    ReleaseGroup(mEntryGroup);
}

otbrError PublisherAvahi::Start(void)
{
    otbrError error      = OTBR_ERROR_NONE;
    int       avahiError = 0;

    assert(mClient == nullptr);

    mClient = avahi_client_new(mPoller->GetAvahiPoll(), AVAHI_CLIENT_NO_FAIL, HandleClientState, this, &avahiError);

    if (avahiError)
    {
        otbrLogErr("Failed to create avahi client: %s!", avahi_strerror(avahiError));
        error = OTBR_ERROR_MDNS;
    }

    return error;
}

bool PublisherAvahi::IsStarted(void) const
{
    return mClient != nullptr;
}

void PublisherAvahi::Stop(void)
{
    mServiceRegistrations.clear();
    mHostRegistrations.clear();

    if (mClient)
    {
        avahi_client_free(mClient);
        mClient = nullptr;
    }
}

void PublisherAvahi::HandleClientState(AvahiClient *aClient, AvahiClientState aState, void *aContext)
{
    static_cast<PublisherAvahi *>(aContext)->HandleClientState(aClient, aState);
}

void PublisherAvahi::HandleGroupState(AvahiEntryGroup *aGroup, AvahiEntryGroupState aState, void *aContext)
{
    static_cast<PublisherAvahi *>(aContext)->HandleGroupState(aGroup, aState);
}

void PublisherAvahi::HandleGroupState(AvahiEntryGroup *aGroup, AvahiEntryGroupState aState)
{
    switch (aState)
    {
    case AVAHI_ENTRY_GROUP_ESTABLISHED:
        otbrLogInfo("Avahi group (@%p) is established", aGroup);
        CallHostOrServiceCallback(aGroup, OTBR_ERROR_NONE);
        break;

    case AVAHI_ENTRY_GROUP_COLLISION:
        otbrLogErr("Avahi group (@%p) name conflicted", aGroup);
        CallHostOrServiceCallback(aGroup, OTBR_ERROR_DUPLICATED);
        break;

    case AVAHI_ENTRY_GROUP_FAILURE:
        otbrLogErr("Avahi group (@%p) failed: %s!", aGroup,
                   avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(aGroup))));
        CallHostOrServiceCallback(aGroup, OTBR_ERROR_MDNS);
        break;

    case AVAHI_ENTRY_GROUP_UNCOMMITED:
    case AVAHI_ENTRY_GROUP_REGISTERING:
        otbrLogErr("Avahi group (@%p) is ready", aGroup);
        break;

    default:
        assert(false);
        break;
    }
}

void PublisherAvahi::CallHostOrServiceCallback(AvahiEntryGroup *aGroup, otbrError aError)
{
    ServiceRegistrationPtr serviceReg;
    HostRegistrationPtr    hostReg;

    if ((serviceReg = FindServiceRegistration(aGroup)) != nullptr)
    {
        std::move(serviceReg->mCallback)(aError);
        if (aError != OTBR_ERROR_NONE)
        {
            RemoveServiceRegistration(serviceReg->mName, serviceReg->mType);
        }
    }
    else if ((hostReg = FindHostRegistration(aGroup)) != nullptr)
    {
        std::move(hostReg->mCallback)(aError);
        if (aError != OTBR_ERROR_NONE)
        {
            RemoveHostRegistration(hostReg->mName);
        }
    }
    else
    {
        otbrLogWarning("No registered service or host matches avahi group @%p", aGroup);
    }
}

AvahiEntryGroup *PublisherAvahi::CreateGroup(AvahiClient *aClient)
{
    AvahiEntryGroup *group = avahi_entry_group_new(aClient, HandleGroupState, this);

    if (group == nullptr)
    {
        otbrLogErr("Failed to create entry avahi group: %s", avahi_strerror(avahi_client_errno(aClient)));
    }

    return group;
}

void PublisherAvahi::ReleaseGroup(AvahiEntryGroup *aGroup)
{
    int error;

    otbrLogInfo("Releasing avahi entry group @%p", aGroup);

    error = avahi_entry_group_reset(aGroup);

    if (error != 0)
    {
        otbrLogErr("Failed to reset entry group for avahi error: %s", avahi_strerror(error));
    }

    error = avahi_entry_group_free(aGroup);
    if (error != 0)
    {
        otbrLogErr("Failed to free entry group for avahi error: %s", avahi_strerror(error));
    }
}

void PublisherAvahi::HandleClientState(AvahiClient *aClient, AvahiClientState aState)
{
    otbrLogInfo("Avahi client state changed to %d", aState);

    switch (aState)
    {
    case AVAHI_CLIENT_S_RUNNING:
        // The server has startup successfully and registered its host
        // name on the network, so it's time to create our services.
        otbrLogInfo("Avahi client is ready");
        mClient = aClient;
        mState  = State::kReady;
        mStateCallback(mState);
        break;

    case AVAHI_CLIENT_FAILURE:
        otbrLogErr("Avahi client failed to start: %s", avahi_strerror(avahi_client_errno(aClient)));
        mState = State::kIdle;
        mStateCallback(mState);
        break;

    case AVAHI_CLIENT_S_COLLISION:
        // Let's drop our registered services. When the server is back
        // in AVAHI_SERVER_RUNNING state we will register them again
        // with the new host name.
        otbrLogErr("Avahi client collision detected: %s", avahi_strerror(avahi_client_errno(aClient)));

        // fall through

    case AVAHI_CLIENT_S_REGISTERING:
        // The server records are now being established. This might be
        // caused by a host name change. We need to wait for our own
        // records to register until the host name is properly established.
        mServiceRegistrations.clear();
        mHostRegistrations.clear();
        break;

    case AVAHI_CLIENT_CONNECTING:
        otbrLogDebug("Avahi client is connecting to the server");
        break;

    default:
        assert(false);
        break;
    }
}

void PublisherAvahi::PublishService(const std::string &aHostName,
                                    const std::string &aName,
                                    const std::string &aType,
                                    const SubTypeList &aSubTypeList,
                                    uint16_t           aPort,
                                    const TxtList &    aTxtList,
                                    ResultCallback &&  aCallback)
{
    otbrError         error             = OTBR_ERROR_NONE;
    int               avahiError        = 0;
    SubTypeList       sortedSubTypeList = SortSubTypeList(aSubTypeList);
    TxtList           sortedTxtList     = SortTxtList(aTxtList);
    const std::string logHostName       = !aHostName.empty() ? aHostName : "localhost";
    std::string       fullHostName;
    AvahiEntryGroup * group = nullptr;

    // Aligned with AvahiStringList
    AvahiStringList  txtBuffer[(kMaxSizeOfTxtRecord - 1) / sizeof(AvahiStringList) + 1];
    AvahiStringList *txtHead = nullptr;

    VerifyOrExit(mState == State::kReady, error = OTBR_ERROR_INVALID_STATE);
    VerifyOrExit(mClient != nullptr, error = OTBR_ERROR_INVALID_STATE);

    if (!aHostName.empty())
    {
        HostRegistrationPtr hostReg = Publisher::FindHostRegistration(aHostName);

        // Make sure that the host has been published.
        VerifyOrExit(hostReg != nullptr, error = OTBR_ERROR_INVALID_ARGS);
        fullHostName = MakeFullHostName(aHostName);
    }

    aCallback = HandleDuplicateServiceRegistration(aHostName, aName, aType, sortedSubTypeList, aPort, sortedTxtList,
                                                   std::move(aCallback));
    if (aCallback.IsNull())
    {
        ExitNow();
    }

    SuccessOrExit(error = TxtListToAvahiStringList(aTxtList, txtBuffer, sizeof(txtBuffer), txtHead));
    VerifyOrExit((group = CreateGroup(mClient)) != nullptr, error = OTBR_ERROR_MDNS);
    avahiError = avahi_entry_group_add_service_strlst(group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, AvahiPublishFlags{},
                                                      aName.c_str(), aType.c_str(),
                                                      /* domain */ nullptr, fullHostName.c_str(), aPort, txtHead);
    SuccessOrExit(avahiError);

    for (const std::string &subType : aSubTypeList)
    {
        otbrLogInfo("Add subtype %s for service %s.%s", subType.c_str(), aName.c_str(), aType.c_str());
        std::string fullSubType = subType + "._sub." + aType;
        avahiError              = avahi_entry_group_add_service_subtype(group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
                                                           AvahiPublishFlags{}, aName.c_str(), aType.c_str(),
                                                           /* domain */ nullptr, fullSubType.c_str());
        SuccessOrExit(avahiError);
    }

    otbrLogInfo("Commit avahi service %s.%s", aName.c_str(), aType.c_str());
    avahiError = avahi_entry_group_commit(group);
    SuccessOrExit(avahiError);

    AddServiceRegistration(std::make_shared<AvahiServiceRegistration>(aHostName, aName, aType, sortedSubTypeList, aPort,
                                                                      sortedTxtList, std::move(aCallback), group));

exit:
    if (avahiError != 0 || error != OTBR_ERROR_NONE)
    {
        if (avahiError != 0)
        {
            error = OTBR_ERROR_MDNS;
            otbrLogErr("Failed to publish service for avahi error: %s!", avahi_strerror(avahiError));
        }

        if (group != nullptr)
        {
            ReleaseGroup(group);
        }
        std::move(aCallback)(error);
    }
}

void PublisherAvahi::UnpublishService(const std::string &aName, const std::string &aType, ResultCallback &&aCallback)
{
    RemoveServiceRegistration(aName, aType);
    std::move(aCallback)(OTBR_ERROR_NONE);
}

void PublisherAvahi::PublishHost(const std::string &         aName,
                                 const std::vector<uint8_t> &aAddress,
                                 ResultCallback &&           aCallback)
{
    otbrError        error      = OTBR_ERROR_NONE;
    int              avahiError = 0;
    std::string      fullHostName;
    AvahiAddress     address;
    AvahiEntryGroup *group = nullptr;

    VerifyOrExit(mState == State::kReady, error = OTBR_ERROR_INVALID_STATE);
    VerifyOrExit(mClient != nullptr, error = OTBR_ERROR_INVALID_STATE);
    VerifyOrExit(aAddress.size() == sizeof(address.data.ipv6.address), error = OTBR_ERROR_INVALID_ARGS);

    aCallback = HandleDuplicateHostRegistration(aName, aAddress, std::move(aCallback));
    if (aCallback.IsNull())
    {
        ExitNow();
    }

    address.proto = AVAHI_PROTO_INET6;
    memcpy(address.data.ipv6.address, aAddress.data(), aAddress.size());
    fullHostName = MakeFullHostName(aName);

    VerifyOrExit((group = CreateGroup(mClient)) != nullptr, error = OTBR_ERROR_MDNS);
    avahiError = avahi_entry_group_add_address(group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, AVAHI_PUBLISH_NO_REVERSE,
                                               fullHostName.c_str(), &address);
    SuccessOrExit(avahiError);

    otbrLogInfo("Commit avahi host %s", aName.c_str());
    avahiError = avahi_entry_group_commit(group);
    SuccessOrExit(avahiError);

    AddHostRegistration(std::make_shared<AvahiHostRegistration>(aName, aAddress, std::move(aCallback), group));

exit:
    if (avahiError != 0 || error != OTBR_ERROR_NONE)
    {
        if (avahiError != 0)
        {
            error = OTBR_ERROR_MDNS;
            otbrLogErr("Failed to publish host for avahi error: %s!", avahi_strerror(avahiError));
        }

        if (group != nullptr)
        {
            ReleaseGroup(group);
        }
        std::move(aCallback)(error);
    }
}

void PublisherAvahi::UnpublishHost(const std::string &aName, ResultCallback &&aCallback)
{
    RemoveHostRegistration(aName);
    std::move(aCallback)(OTBR_ERROR_NONE);
}

otbrError PublisherAvahi::TxtListToAvahiStringList(const TxtList &   aTxtList,
                                                   AvahiStringList * aBuffer,
                                                   size_t            aBufferSize,
                                                   AvahiStringList *&aHead)
{
    otbrError        error = OTBR_ERROR_NONE;
    size_t           used  = 0;
    AvahiStringList *last  = nullptr;
    AvahiStringList *curr  = aBuffer;

    aHead = nullptr;
    for (const auto &txtEntry : aTxtList)
    {
        const char *   name        = txtEntry.mName.c_str();
        size_t         nameLength  = txtEntry.mName.length();
        const uint8_t *value       = txtEntry.mValue.data();
        size_t         valueLength = txtEntry.mValue.size();
        // +1 for the size of "=", avahi doesn't need '\0' at the end of the entry
        size_t needed = sizeof(AvahiStringList) - sizeof(AvahiStringList::text) + nameLength + valueLength + 1;

        VerifyOrExit(used + needed <= aBufferSize, error = OTBR_ERROR_INVALID_ARGS);
        curr->next = last;
        last       = curr;
        memcpy(curr->text, name, nameLength);
        curr->text[nameLength] = '=';
        memcpy(curr->text + nameLength + 1, value, valueLength);
        curr->size = nameLength + valueLength + 1;
        {
            const uint8_t *next = curr->text + curr->size;
            curr                = OTBR_ALIGNED(next, AvahiStringList *);
        }
        used = static_cast<size_t>(reinterpret_cast<uint8_t *>(curr) - reinterpret_cast<uint8_t *>(aBuffer));
    }
    SuccessOrExit(error);
    aHead = last;
exit:
    return error;
}

Publisher::ServiceRegistrationPtr PublisherAvahi::FindServiceRegistration(const AvahiEntryGroup *aEntryGroup) const
{
    ServiceRegistrationPtr result = nullptr;

    for (auto &kv : mServiceRegistrations)
    {
        auto serviceReg = std::dynamic_pointer_cast<AvahiServiceRegistration>(kv.second);
        if (serviceReg != nullptr && serviceReg->GetEntryGroup() == aEntryGroup)
        {
            result = serviceReg;
            break;
        }
    }

    return result;
}

Publisher::HostRegistrationPtr PublisherAvahi::FindHostRegistration(const AvahiEntryGroup *aEntryGroup) const
{
    HostRegistrationPtr result = nullptr;

    for (auto &kv : mHostRegistrations)
    {
        auto hostReg = std::dynamic_pointer_cast<AvahiHostRegistration>(kv.second);
        if (hostReg != nullptr && hostReg->GetEntryGroup() == aEntryGroup)
        {
            result = hostReg;
            break;
        }
    }

    return result;
}

void PublisherAvahi::SubscribeService(const std::string &aType, const std::string &aInstanceName)
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
        mSubscribedServices.back().Resolve(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, aInstanceName, aType);
    }
}

void PublisherAvahi::UnsubscribeService(const std::string &aType, const std::string &aInstanceName)
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

void PublisherAvahi::OnServiceResolved(ServiceSubscription &aService)
{
    otbrLogInfo("Service %s is resolved successfully: %s host %s addresses %zu", aService.mType.c_str(),
                aService.mInstanceInfo.mName.c_str(), aService.mInstanceInfo.mHostName.c_str(),
                aService.mInstanceInfo.mAddresses.size());
    if (mDiscoveredServiceInstanceCallback != nullptr)
    {
        mDiscoveredServiceInstanceCallback(aService.mType, aService.mInstanceInfo);
    }
}

void PublisherAvahi::OnServiceResolveFailed(const ServiceSubscription &aService, int aErrorCode)
{
    otbrLogWarning("Service %s resolving failed: code=%d", aService.mType.c_str(), aErrorCode);
}

void PublisherAvahi::OnHostResolved(HostSubscription &aHost)
{
    otbrLogInfo("Host %s is resolved successfully: host %s addresses %zu ttl %u", aHost.mHostName.c_str(),
                aHost.mHostInfo.mHostName.c_str(), aHost.mHostInfo.mAddresses.size(), aHost.mHostInfo.mTtl);
    if (mDiscoveredHostCallback != nullptr)
    {
        mDiscoveredHostCallback(aHost.mHostName, aHost.mHostInfo);
    }
}

void PublisherAvahi::OnHostResolveFailed(const HostSubscription &aHost, int aErrorCode)
{
    otbrLogWarning("Host %s resolving failed: code=%d", aHost.mHostName.c_str(), aErrorCode);
}

void PublisherAvahi::SubscribeHost(const std::string &aHostName)
{
    mSubscribedHosts.emplace_back(*this, aHostName);

    otbrLogInfo("subscribe host %s (total %zu)", aHostName.c_str(), mSubscribedHosts.size());

    mSubscribedHosts.back().Resolve();
}

void PublisherAvahi::UnsubscribeHost(const std::string &aHostName)
{
    HostSubscriptionList::iterator it =
        std::find_if(mSubscribedHosts.begin(), mSubscribedHosts.end(),
                     [&aHostName](const HostSubscription &aHost) { return aHost.mHostName == aHostName; });

    assert(it != mSubscribedHosts.end());

    it->Release();
    mSubscribedHosts.erase(it);

    otbrLogInfo("unsubscribe host %s (remaining %d)", aHostName.c_str(), mSubscribedHosts.size());
}

Publisher *Publisher::Create(StateCallback aStateCallback)
{
    return new PublisherAvahi(std::move(aStateCallback));
}

void Publisher::Destroy(Publisher *aPublisher)
{
    delete static_cast<PublisherAvahi *>(aPublisher);
}

void PublisherAvahi::ServiceSubscription::Browse(void)
{
    assert(mPublisherAvahi->mClient != nullptr);

    otbrLogInfo("browse service %s", mType.c_str());
    mServiceBrowser =
        avahi_service_browser_new(mPublisherAvahi->mClient, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, mType.c_str(),
                                  /* domain */ nullptr, static_cast<AvahiLookupFlags>(0), HandleBrowseResult, this);
    if (!mServiceBrowser)
    {
        otbrLogWarning("failed to browse service %s: %s", mType.c_str(),
                       avahi_strerror(avahi_client_errno(mPublisherAvahi->mClient)));
    }
}

void PublisherAvahi::ServiceSubscription::Release(void)
{
    if (mServiceBrowser != nullptr)
    {
        avahi_service_browser_free(mServiceBrowser);
        mServiceBrowser = nullptr;
    }
    if (mServiceResolver != nullptr)
    {
        avahi_service_resolver_free(mServiceResolver);
        mServiceResolver = nullptr;
    }
}

void PublisherAvahi::ServiceSubscription::HandleBrowseResult(AvahiServiceBrowser *  aServiceBrowser,
                                                             AvahiIfIndex           aInterfaceIndex,
                                                             AvahiProtocol          aProtocol,
                                                             AvahiBrowserEvent      aEvent,
                                                             const char *           aName,
                                                             const char *           aType,
                                                             const char *           aDomain,
                                                             AvahiLookupResultFlags aFlags,
                                                             void *                 aContext)
{
    static_cast<PublisherAvahi::ServiceSubscription *>(aContext)->HandleBrowseResult(
        aServiceBrowser, aInterfaceIndex, aProtocol, aEvent, aName, aType, aDomain, aFlags);
}

void PublisherAvahi::ServiceSubscription::HandleBrowseResult(AvahiServiceBrowser *  aServiceBrowser,
                                                             AvahiIfIndex           aInterfaceIndex,
                                                             AvahiProtocol          aProtocol,
                                                             AvahiBrowserEvent      aEvent,
                                                             const char *           aName,
                                                             const char *           aType,
                                                             const char *           aDomain,
                                                             AvahiLookupResultFlags aFlags)
{
    OTBR_UNUSED_VARIABLE(aServiceBrowser);
    OTBR_UNUSED_VARIABLE(aProtocol);
    OTBR_UNUSED_VARIABLE(aDomain);

    assert(mServiceBrowser == aServiceBrowser);

    otbrLogInfo("browse service reply: %s.%s inf %u, flags=%u", aName, aType, aInterfaceIndex, aFlags);

    if (aEvent == AVAHI_BROWSER_FAILURE)
    {
        mPublisherAvahi->OnServiceResolveFailed(*this, avahi_client_errno(mPublisherAvahi->mClient));
    }
    else
    {
        Resolve(aInterfaceIndex, aProtocol, aName, aType);
    }
    if (mServiceBrowser != nullptr)
    {
        avahi_service_browser_free(mServiceBrowser);
        mServiceBrowser = nullptr;
    }
}

void PublisherAvahi::ServiceSubscription::Resolve(uint32_t           aInterfaceIndex,
                                                  AvahiProtocol      aProtocol,
                                                  const std::string &aInstanceName,
                                                  const std::string &aType)
{
    otbrLogInfo("resolve service %s %s inf %d", aInstanceName.c_str(), aType.c_str(), aInterfaceIndex);
    mServiceResolver = avahi_service_resolver_new(
        mPublisherAvahi->mClient, aInterfaceIndex, aProtocol, aInstanceName.c_str(), aType.c_str(),
        /* domain */ nullptr, AVAHI_PROTO_INET6, static_cast<AvahiLookupFlags>(0), HandleResolveResult, this);
    if (!mServiceResolver)
    {
        otbrLogErr("failed to resolve serivce %s: %s", mType.c_str(),
                   avahi_strerror(avahi_client_errno(mPublisherAvahi->mClient)));
    }
}

void PublisherAvahi::ServiceSubscription::HandleResolveResult(AvahiServiceResolver * aServiceResolver,
                                                              AvahiIfIndex           aInterfaceIndex,
                                                              AvahiProtocol          aProtocol,
                                                              AvahiResolverEvent     aEvent,
                                                              const char *           aName,
                                                              const char *           aType,
                                                              const char *           aDomain,
                                                              const char *           aHostName,
                                                              const AvahiAddress *   aAddress,
                                                              uint16_t               aPort,
                                                              AvahiStringList *      aTxt,
                                                              AvahiLookupResultFlags aFlags,
                                                              void *                 aContext)
{
    static_cast<PublisherAvahi::ServiceSubscription *>(aContext)->HandleResolveResult(
        aServiceResolver, aInterfaceIndex, aProtocol, aEvent, aName, aType, aDomain, aHostName, aAddress, aPort, aTxt,
        aFlags);
}

void PublisherAvahi::ServiceSubscription::HandleResolveResult(AvahiServiceResolver * aServiceResolver,
                                                              AvahiIfIndex           aInterfaceIndex,
                                                              AvahiProtocol          aProtocol,
                                                              AvahiResolverEvent     aEvent,
                                                              const char *           aName,
                                                              const char *           aType,
                                                              const char *           aDomain,
                                                              const char *           aHostName,
                                                              const AvahiAddress *   aAddress,
                                                              uint16_t               aPort,
                                                              AvahiStringList *      aTxt,
                                                              AvahiLookupResultFlags aFlags)
{
    OT_UNUSED_VARIABLE(aServiceResolver);
    OT_UNUSED_VARIABLE(aInterfaceIndex);
    OT_UNUSED_VARIABLE(aProtocol);
    OT_UNUSED_VARIABLE(aType);
    OT_UNUSED_VARIABLE(aDomain);

    char       buf[AVAHI_ADDRESS_STR_MAX];
    Ip6Address address;
    size_t     totalTxtSize = 0;

    assert(mServiceResolver == aServiceResolver);
    VerifyOrExit(
        aEvent == AVAHI_RESOLVER_FOUND,
        otbrLogErr("failed to resolve service: %s", avahi_strerror(avahi_client_errno(mPublisherAvahi->mClient))));
    VerifyOrExit(aHostName != nullptr, otbrLogErr("host name is null"));

    mInstanceInfo.mName     = aName;
    mInstanceInfo.mHostName = std::string(aHostName) + ".";
    mInstanceInfo.mPort     = aPort;
    avahi_address_snprint(buf, sizeof(buf), aAddress);
    VerifyOrExit(otbrError::OTBR_ERROR_NONE == Ip6Address::FromString(buf, address),
                 otbrLogErr("failed to parse the IP address: %s", buf));

    otbrLogDebug("resolve service reply: flags=%u, host=%s", aFlags, aHostName);

    VerifyOrExit(!address.IsLinkLocal() && !address.IsMulticast() && !address.IsLoopback() && !address.IsUnspecified(),
                 otbrLogDebug("ignoring address %s", address.ToString().c_str()));

    mInstanceInfo.mAddresses.push_back(address);

    // TODO priority
    // TODO weight
    // TODO use a more proper TTL
    mInstanceInfo.mTtl = kDefaultTtl;
    for (auto p = aTxt; p; p = avahi_string_list_get_next(p))
    {
        totalTxtSize += avahi_string_list_get_size(p) + 1;
    }
    mInstanceInfo.mTxtData.resize(totalTxtSize);
    avahi_string_list_serialize(aTxt, mInstanceInfo.mTxtData.data(), totalTxtSize);

    otbrLogDebug("resolve service reply: address=%s, ttl=%u", address.ToString().c_str(), mInstanceInfo.mTtl);

    mPublisherAvahi->OnServiceResolved(*this);

exit:
    if (avahi_client_errno(mPublisherAvahi->mClient) != AVAHI_OK)
    {
        mPublisherAvahi->OnServiceResolveFailed(*this, avahi_client_errno(mPublisherAvahi->mClient));
    }
    if (mServiceBrowser != nullptr)
    {
        avahi_service_resolver_free(mServiceResolver);
        mServiceResolver = nullptr;
    }
}

void PublisherAvahi::HostSubscription::Release(void)
{
    if (mRecordBrowser != nullptr)
    {
        avahi_record_browser_free(mRecordBrowser);
        mRecordBrowser = nullptr;
    }
}

void PublisherAvahi::HostSubscription::Resolve(void)
{
    std::string fullHostName = MakeFullHostName(mHostName);

    otbrLogDebug("resolve host %s inf %d", fullHostName.c_str(), AVAHI_IF_UNSPEC);
    mRecordBrowser = avahi_record_browser_new(mPublisherAvahi->mClient, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
                                              fullHostName.c_str(), AVAHI_DNS_CLASS_IN, AVAHI_DNS_TYPE_AAAA,
                                              static_cast<AvahiLookupFlags>(0), HandleResolveResult, this);
    if (!mRecordBrowser)
    {
        otbrLogErr("failed to resolve host %s: %s", fullHostName.c_str(),
                   avahi_strerror(avahi_client_errno(mPublisherAvahi->mClient)));
    }
}

void PublisherAvahi::HostSubscription::HandleResolveResult(AvahiRecordBrowser *   aRecordBrowser,
                                                           AvahiIfIndex           aInterfaceIndex,
                                                           AvahiProtocol          aProtocol,
                                                           AvahiBrowserEvent      aEvent,
                                                           const char *           aName,
                                                           uint16_t               aClazz,
                                                           uint16_t               aType,
                                                           const void *           aRdata,
                                                           size_t                 aSize,
                                                           AvahiLookupResultFlags aFlags,
                                                           void *                 aContext)
{
    static_cast<PublisherAvahi::HostSubscription *>(aContext)->HandleResolveResult(
        aRecordBrowser, aInterfaceIndex, aProtocol, aEvent, aName, aClazz, aType, aRdata, aSize, aFlags);
}

void PublisherAvahi::HostSubscription::HandleResolveResult(AvahiRecordBrowser *   aRecordBrowser,
                                                           AvahiIfIndex           aInterfaceIndex,
                                                           AvahiProtocol          aProtocol,
                                                           AvahiBrowserEvent      aEvent,
                                                           const char *           aName,
                                                           uint16_t               aClazz,
                                                           uint16_t               aType,
                                                           const void *           aRdata,
                                                           size_t                 aSize,
                                                           AvahiLookupResultFlags aFlags)
{
    OTBR_UNUSED_VARIABLE(aRecordBrowser);
    OTBR_UNUSED_VARIABLE(aInterfaceIndex);
    OTBR_UNUSED_VARIABLE(aProtocol);
    OTBR_UNUSED_VARIABLE(aEvent);
    OTBR_UNUSED_VARIABLE(aClazz);
    OTBR_UNUSED_VARIABLE(aType);
    OTBR_UNUSED_VARIABLE(aFlags);

    Ip6Address address = *static_cast<const uint8_t(*)[16]>(aRdata);
    assert(mRecordBrowser == aRecordBrowser);
    VerifyOrExit(!address.IsLinkLocal() && !address.IsMulticast() && !address.IsLoopback() && !address.IsUnspecified());
    VerifyOrExit(aSize == 16, otbrLogErr("unexpected address data length: %u", aSize));
    otbrLogInfo("resolved host address: %s", address.ToString().c_str());

    mHostInfo.mHostName = std::string(aName) + ".";
    mHostInfo.mAddresses.push_back(std::move(address));
    // TODO: Use a more proper TTL
    mHostInfo.mTtl = kDefaultTtl;
    mPublisherAvahi->OnHostResolved(*this);

exit:
    if (avahi_client_errno(mPublisherAvahi->mClient) != AVAHI_OK)
    {
        mPublisherAvahi->OnHostResolveFailed(*this, avahi_client_errno(mPublisherAvahi->mClient));
    }
    if (mRecordBrowser != nullptr)
    {
        avahi_record_browser_free(mRecordBrowser);
        mRecordBrowser = nullptr;
    }
}

} // namespace Mdns

} // namespace otbr

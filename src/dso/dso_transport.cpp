#include "openthread/platform/dso_transport.h"
#include "dso_transport.hpp"
#include <list>
#include <memory>
#include "mbedtls/net_sockets.h"
#include "openthread/openthread-system.h"

std::map<otPlatDsoConnection *, otbr::dso::DsoConnection *> otbr::dso::DsoConnection::sMap;

std::list<std::unique_ptr<otbr::dso::DsoConnection>> sConnections;
// static bool                                          sEnabled          = true;
static bool                sListeningEnabled = false;
static mbedtls_net_context sListeningCtx;
static const uint16_t      kListeningPort = 853;

// TODO ensure the socket is closed when disabled
extern "C" void otPlatDsoEnableListening(otInstance *aInstance, bool aEnabled)
{
    OT_UNUSED_VARIABLE(aInstance);
    OT_UNUSED_VARIABLE(aEnabled);
    VerifyOrExit(aEnabled != sListeningEnabled);

    sListeningEnabled = aEnabled;
    otbrLogInfo("DSO listening enabled: %s", sListeningEnabled ? "Yes" : "No");
    if (sListeningEnabled)
    {
        sListeningCtx.fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        otbrLogInfo("!!!!!!!! ifrname %s", otSysGetInfraNetifName());
        int ret;
        if ((ret = setsockopt(sListeningCtx.fd, SOL_SOCKET, SO_BINDTODEVICE, otSysGetInfraNetifName(),
                              strlen(otSysGetInfraNetifName()))) < 0)
        {
            perror("Server-setsockopt() error for SO_BINDTODEVICE");
            printf("Server-setsockopt() error for SO_BINDTODEVICE %s\n", strerror(errno));
            std::abort();
        }
        int n;
        if (setsockopt(sListeningCtx.fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&n, sizeof(n)) != 0)
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

        if (bind(sListeningCtx.fd, (struct sockaddr *)&sockAddr, sizeof(sockAddr)) != 0)
        {
            otbrLogInfo("[srpl] Failed to bind socket");
            std::abort();
            //            DieNow(OT_EXIT_ERROR_ERRNO);
        }
        mbedtls_net_set_nonblock(&sListeningCtx);

        if (listen(sListeningCtx.fd, 10) != 0)
        {
            otbrLogInfo("[srpl] Failed to listen on socket");
            std::abort();
            //            DieNow(OT_EXIT_ERROR_ERRNO);
        }
        otbrLogInfo("Listening socket created!!!");
    }
    else
    {
        mbedtls_net_close(&sListeningCtx);
        sConnections.clear();
    }

exit:
    return;
}

extern "C" void otPlatDsoConnect(otPlatDsoConnection *aConnection, const otSockAddr *aPeerSockAddr)
{
    auto conn = otbr::dso::DsoConnection::FindOrCreate(aConnection);
    conn->Connect(aPeerSockAddr);
}

extern "C" void otPlatDsoSend(otPlatDsoConnection *aConnection, otMessage *aMessage)
{
    OT_UNUSED_VARIABLE(aConnection);
    OT_UNUSED_VARIABLE(aMessage);

    auto conn = otbr::dso::DsoConnection::Find(aConnection);
    VerifyOrExit(conn != nullptr);
    conn->Send(aMessage);

exit:
    otMessageFree(aMessage);
}

extern "C" void otPlatDsoDisconnect(otPlatDsoConnection *aConnection, otPlatDsoDisconnectMode aMode)
{
    OT_UNUSED_VARIABLE(aConnection);
    OT_UNUSED_VARIABLE(aMode);
    auto conn = otbr::dso::DsoConnection::Find(aConnection);
    VerifyOrExit(conn != nullptr);
    conn->Disconnect(aMode);

    otbr::dso::DsoConnection::sMap.erase(aConnection);

    for (auto it = sConnections.begin(); it != sConnections.end(); ++it)
    {
        if (conn == it->get())
        {
            otbrLogInfo("!!!!! erased: %p", it->get());
            sConnections.erase(it);
            break;
        }
    }

exit:
    return;
}

namespace otbr {
namespace dso {

void AcceptIncomingConnections(otInstance *aInstance)
{
    VerifyOrExit(sListeningEnabled);

    while (true)
    {
        mbedtls_net_context  incomingCtx;
        uint8_t              incomingAddrBuf[sizeof(sockaddr_in6)];
        size_t               len = 0;
        otSockAddr           addr;
        in6_addr            *addrIn6;
        otPlatDsoConnection *conn;

        int ret = mbedtls_net_accept(&sListeningCtx, &incomingCtx, &incomingAddrBuf, sizeof(incomingAddrBuf), &len);

        VerifyOrExit(ret == 0, otbrLogInfo("!!!!! error accepting connection: %s", otbr::dso::MbedErrorToString(ret)));

        otbrLogInfo("!!!!! address size===== %ld", len);

        if (mbedtls_net_set_nonblock(&incomingCtx))
        {
            continue;
        }

        if (len == OT_IP6_ADDRESS_SIZE)
        { // TODO: the way of handling addr may be wrong
            addrIn6 = reinterpret_cast<in6_addr *>(incomingAddrBuf);
            memcpy(&addr.mAddress.mFields.m8, &addrIn6, len);
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
            otbr::dso::DsoConnection::Create(conn, incomingCtx)->mConnected = true;
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
} // namespace dso
} // namespace otbr

extern "C" void platformDsoProcess(otInstance *aInstance)
{
    otbr::dso::DsoConnection::ProcessAll();
    otbr::dso::AcceptIncomingConnections(aInstance);
}
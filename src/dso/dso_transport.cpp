#include "openthread/platform/dso_transport.h"
#include "dso_transport.hpp"
//#include "system.hpp"
#include <list>
#include <memory>
//#include "common/string.hpp"
#include "mbedtls/net_sockets.h"
#include "openthread/openthread-system.h"
//#include "net/dns_dso.hpp"
//#include "posix/platform/platform-posix.h"

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
    auto _ = CDLogger("Accept incoming connections");
    VerifyOrExit(sListeningEnabled);

    while (true)
    {
        otbrLogInfo("$$$$$$$$$$$$$$$$$$$ waiting for incoming connections ");
        mbedtls_net_context  incomingCtx;
        uint8_t              incomingAddrBuf[sizeof(sockaddr_in6)];
        size_t               len = 0;
        otSockAddr           addr;
        in6_addr            *addrIn6;
        in_addr             *addrIn;
        otPlatDsoConnection *conn;

        int ret = mbedtls_net_accept(&sListeningCtx, &incomingCtx, &incomingAddrBuf, sizeof(incomingAddrBuf), &len);
        if (ret < 0)
        {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ)
            {
                ExitNow();
            }
            else
            {
                otbrLogInfo("!!!!! error accepting connection: %s", otbr::dso::MbedErrorToString(ret));
            }
        }
        otbrLogInfo("!!!!! address size===== %ld", len);
        if (len != OT_IP6_ADDRESS_SIZE && len != 4)
        {
            otbrLogInfo("!!!!! unexpected address size: %ld", len);
            ExitNow();
        }

        SuccessOrDie(mbedtls_net_set_nonblock(&incomingCtx), "Die");

        if (len == OT_IP6_ADDRESS_SIZE)
        { // TODO: the way of handling addr may be wrong
            addrIn6 = reinterpret_cast<in6_addr *>(incomingAddrBuf);
            memcpy(&addr.mAddress.mFields.m8, &addrIn6, len);
            addr.mPort = 0; // TODO
        }
        else if (len == 4)
        {
            addrIn = reinterpret_cast<in_addr *>(incomingAddrBuf);
            memset(&addr.mAddress, 0, sizeof(addr.mAddress));
            memcpy(addr.mAddress.mFields.m32 + 3, &addrIn, len);
            addr.mAddress.mFields.m16[5] = 0xff;
            addr.mAddress.mFields.m16[6] = 0xff;
            addr.mPort                   = 0; // TODO
            otbrLogInfo("!!!!! IPV4 incoming connection: %p", addrIn);
        }
        else
        {
            otbrLogInfo("!!!!! unknown address type !!!! ");
            ExitNow();
        }
        conn = otPlatDsoAccept(aInstance, &addr);

        //        otbrLogInfo("!!!!! accepting connection: %16x", incomingAddrBuf);

        if (conn != nullptr)
        {
            otPlatDsoHandleConnected(conn);
            otbr::dso::DsoConnection::Create(conn, incomingCtx)->mConnected = true;
            otbrLogInfo("handle connected !!!!");
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
    auto _ = otbr::dso::CDLogger("platform Dso Process");

    otbr::dso::DsoConnection::ProcessAll();
    otbr::dso::AcceptIncomingConnections(aInstance);
}
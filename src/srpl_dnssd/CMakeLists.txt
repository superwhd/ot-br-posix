add_library(otbr-srpl-dnssd
    srpl_dnssd.cpp
    srpl_dnssd.hpp
    )

target_link_libraries(otbr-srpl-dnssd PRIVATE
    $<$<BOOL:${OTBR_MDNS}>:otbr-mdns>
    otbr-common
    )

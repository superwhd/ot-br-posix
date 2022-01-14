add_library(otbr-srpl
    srpl_dnssd.cpp
    srpl_dnssd.hpp
    )

target_link_libraries(otbr-srpl PRIVATE
    $<$<BOOL:${OTBR_MDNS}>:otbr-mdns>
    otbr-common
    )

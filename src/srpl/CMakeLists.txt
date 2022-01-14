add_library(otbr-srpl
    srp_replication.cpp
    )

target_link_libraries(otbr-srpl PRIVATE
    $<$<BOOL:${OTBR_MDNS}>:otbr-mdns>
    otbr-common
    )

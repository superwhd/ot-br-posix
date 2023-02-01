add_library(otbr-dso
    dso_transport.cpp
    dso_transport.hpp
    )

target_link_libraries(otbr-dso PRIVATE
    otbr-common
    mbedtls
    )

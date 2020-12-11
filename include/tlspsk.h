#ifndef WIFIPSK_H_INCLUDED
#define WIFIPSK_H_INCLUDED

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

namespace tlspsk
{
    struct ctr_drbg_ctx
    {
        mbedtls_ctr_drbg_context m_ctr_drbg;
        ctr_drbg_ctx();
        ~ctr_drbg_ctx();
    };

    struct entropy_ctx
    {
        mbedtls_entropy_context m_entropy;
        entropy_ctx();
        ~entropy_ctx();
    };

    struct ssl_conf_ctx
    {
        mbedtls_ssl_config m_config;
        ssl_conf_ctx();
        ~ssl_conf_ctx();
    };

    struct ssl_ctx
    {
        mbedtls_ssl_context m_ssl;
        ssl_ctx();
        ~ssl_ctx();
    };
}; // namespace tlspsk

#endif //WIFIPSK_H_INCLUDED

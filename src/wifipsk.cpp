#include "wifipsk.h"

wifipsk::ctr_drbg_ctx::ctr_drbg_ctx() { mbedtls_ctr_drbg_init(&m_ctr_drbg); }
wifipsk::ctr_drbg_ctx::~ctr_drbg_ctx() { mbedtls_ctr_drbg_free(&m_ctr_drbg); }

wifipsk::entropy_ctx::entropy_ctx() { mbedtls_entropy_init(&m_entropy); }
wifipsk::entropy_ctx::~entropy_ctx() { mbedtls_entropy_free(&m_entropy); }

wifipsk::ssl_conf_ctx::ssl_conf_ctx() { mbedtls_ssl_config_init(&m_config); }
wifipsk::ssl_conf_ctx::~ssl_conf_ctx() { mbedtls_ssl_config_free(&m_config); }

wifipsk::ssl_ctx::ssl_ctx() { mbedtls_ssl_init(&m_ssl); }
wifipsk::ssl_ctx::~ssl_ctx() { mbedtls_ssl_free(&m_ssl); }

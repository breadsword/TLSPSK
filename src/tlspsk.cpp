#include "tlspsk.h"

tlspsk::ctr_drbg_ctx::ctr_drbg_ctx() { mbedtls_ctr_drbg_init(&m_ctr_drbg); }
tlspsk::ctr_drbg_ctx::~ctr_drbg_ctx() { mbedtls_ctr_drbg_free(&m_ctr_drbg); }

tlspsk::entropy_ctx::entropy_ctx() { mbedtls_entropy_init(&m_entropy); }
tlspsk::entropy_ctx::~entropy_ctx() { mbedtls_entropy_free(&m_entropy); }

tlspsk::ssl_conf_ctx::ssl_conf_ctx() { mbedtls_ssl_config_init(&m_config); }
tlspsk::ssl_conf_ctx::~ssl_conf_ctx() { mbedtls_ssl_config_free(&m_config); }

tlspsk::ssl_ctx::ssl_ctx() { mbedtls_ssl_init(&m_ssl); }
tlspsk::ssl_ctx::~ssl_ctx() { mbedtls_ssl_free(&m_ssl); }

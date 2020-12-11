#ifndef WIFISPKCLIENT_H_INCLUDED
#define WIFISPKCLIENT_H_INCLUDED

#include <gsl-lite/gsl-lite.hpp>
#include <string>

#include <client.h>
#include "tlspsk_raii.h"

class TLSPSKConnection
{
public:
    static constexpr auto keylen_bits = 128;
    typedef gsl::span<const uint8_t> psk_t;
    typedef gsl::span<const char> string_t;
    static constexpr uint32_t ssl_timeout = 2000;

    TLSPSKConnection(
        Client &_client,
        const std::string _psk_id, psk_t _psk,
        const std::string _pers = "");

    // forbid copying
    TLSPSKConnection(const TLSPSKConnection &) = delete;
    TLSPSKConnection &operator=(const TLSPSKConnection &) = delete;
    TLSPSKConnection(TLSPSKConnection &&) = delete;
    TLSPSKConnection &operator=(TLSPSKConnection &&) = delete;

    int connect();
    bool available();

    size_t write(const uint8_t *buf, size_t size);
    int read(uint8_t *buf, size_t size);

private:
    tlspsk::entropy_ctx entropy;
    tlspsk::ctr_drbg_ctx ctr_drbg;
    tlspsk::ssl_conf_ctx conf;
    tlspsk::ssl_ctx ssl;

    static int tls_read_timeout(void *ctx, uint8_t *buf, size_t len, uint32_t timeout);
    static int tls_write(void *ctx, const uint8_t *buf, size_t len);
    size_t writeraw(const uint8_t *buf, size_t size);
    int readraw(uint8_t *buf, size_t size, uint32_t timeout_ms);

    Client &client;

    /// write at least some bytes
    int tls_write_some(const unsigned char *buf, size_t len);

    // set up the environment for ssl connection (entropy, rngs, config, ciphers, keys)
    int setup_ssl(string_t pers, string_t psk_id, psk_t psk);
    // make connection between actual socket and ssl machinery, perform handshake
    int ssl_handshake();
};

#endif //WIFISPKCLIENT_H_INCLUDED

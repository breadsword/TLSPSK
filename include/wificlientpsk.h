#ifndef WIFISPKCLIENT_H_INCLUDED
#define WIFISPKCLIENT_H_INCLUDED

#include <wificlient.h>

#include "wifipsk.h"

class WiFiClientPSK : private WiFiClient
{
public:
    constexpr static auto keylen_bits = 128;
    typedef std::array<unsigned char, keylen_bits / 8> psk_t;

    WiFiClientPSK(
        const std::string &_psk_id, const psk_t &_psk,
        const std::string &_pers = "");
    virtual ~WiFiClientPSK();
    WiFiClientPSK(const WiFiClientPSK &) = delete;
    WiFiClientPSK &operator=(const WiFiClientPSK &) = delete;
    WiFiClientPSK(WiFiClientPSK &&) = delete;
    WiFiClientPSK &operator=(WiFiClientPSK &&) = delete;

    virtual int connect(IPAddress ip, uint16_t port) override;
    using WiFiClient::connect;

    virtual size_t write(const uint8_t *buf, size_t size) override;
    virtual size_t write(const uint8_t) override;

    virtual int read(uint8_t *buf, size_t size) override;
    virtual int read() override;

    size_t writeraw(const uint8_t *buf, size_t size);
    int readraw(uint8_t *buf, size_t size, uint32_t timeout_ms);

    using WiFiClient::available;
    using WiFiClient::connected;
    using WiFiClient::flush;
    using WiFiClient::stop;

    static constexpr uint32_t ssl_timeout = 2000;

private:
    wifipsk::entropy_ctx entropy;
    wifipsk::ctr_drbg_ctx ctr_drbg;
    wifipsk::ssl_conf_ctx conf;
    wifipsk::ssl_ctx ssl;

    // additional entropy (device specific)
    const std::string pers;

    // Pre-shared key information
    const std::string psk_id;
    const psk_t m_psk;

    /// write at least some bytes
    int tls_write_some(const unsigned char *buf, size_t len);

    // set up the environment for ssl connection (entropy, rngs, config, ciphers, keys)
    int setup_ssl();
    // make connection between actual socket and ssl machinery, perform handshake
    int ssl_handshake();
};

#endif //WIFISPKCLIENT_H_INCLUDED

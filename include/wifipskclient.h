#ifndef WIFISPKCLIENT_H_INCLUDED
#define WIFISPKCLIENT_H_INCLUDED

#include <wificlient.h>

#include "wifipsk.h"

class WiFiPSKClient : private WiFiClient
{
public:
    typedef std::vector<unsigned char> psk_t;

    WiFiPSKClient(
        const std::string &_psk_id, const psk_t &_psk,
        const std::string &_pers = "");
    virtual ~WiFiPSKClient();
    WiFiPSKClient(const WiFiPSKClient &) = delete;
    WiFiPSKClient &operator=(const WiFiPSKClient &) = delete;
    WiFiPSKClient(WiFiPSKClient &&) = delete;
    WiFiPSKClient &operator=(WiFiPSKClient &&) = delete;

    virtual int connect(IPAddress ip, uint16_t port) override;
    using WiFiClient::connect;

    virtual size_t write(const uint8_t *buf, size_t size) override;

    virtual int read(uint8_t *buf, size_t size) override;

    size_t writeraw(const uint8_t *buf, size_t size);
    int readraw(uint8_t *buf, size_t size, uint32_t timeout_ms);

    using WiFiClient::connected;

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
    psk_t psk;

    /// write at least some bytes
    int tls_write_some(const unsigned char *buf, size_t len);

    // set up the environment for ssl connection (entropy, rngs, config, ciphers, keys)
    int setup_ssl();
    // make connection between actual socket and ssl machinery, perform handshake
    int ssl_handshake();
};

#endif //WIFISPKCLIENT_H_INCLUDED

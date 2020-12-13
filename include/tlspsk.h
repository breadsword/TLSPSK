#ifndef TLSPSK_H_INCLUDED
#define TLSPSK_H_INCLUDED

#include <gsl-lite/gsl-lite.hpp>
#include <string>

#include <client.h>
#include "tlspsk_raii.h"

class TLSPSKConnection
{
public:
    typedef gsl::span<const uint8_t> cbuf_t;
    typedef gsl::span<uint8_t> buf_t;
    typedef gsl::span<const char> string_t;

    static constexpr uint32_t ssl_timeout = 2000;

    TLSPSKConnection(
        Client &_client,
        const std::string _psk_id, cbuf_t _psk,
        const std::string _pers = "");

    // forbid copying
    TLSPSKConnection(const TLSPSKConnection &) = delete;
    TLSPSKConnection &operator=(const TLSPSKConnection &) = delete;
    TLSPSKConnection(TLSPSKConnection &&) = delete;
    TLSPSKConnection &operator=(TLSPSKConnection &&) = delete;

    /// Establish TLS-connection on top of connection in client
    ///
    /// \return 1 on success, <0 on error
    int connect();
    /// Check, if data is available in Client or in internal TLS buffer
    bool available();

    /// Send size bytes from buf over TLS connection, return number of bytes sent
    ssize_t write(const uint8_t *buf, size_t size);
    /// Send the data in the passed span overt eh TLS connection , return number of bytes sent
    ssize_t write(cbuf_t);
    /// Read at most size (decrypted) bytes into buf, return number of bytes read
    ssize_t read(uint8_t *buf, size_t size);
    /// Read (decrypted) data into span, at most the span's length, return number of bytes read
    ssize_t read(buf_t);

    int last_error() const;
    std::string error_message(const int errnum);

private:
    tlspsk::entropy_ctx entropy;
    tlspsk::ctr_drbg_ctx ctr_drbg;
    tlspsk::ssl_conf_ctx conf;
    tlspsk::ssl_ctx ssl;

    int m_last_error;

    /// Use TLSPSKConnection object in ctx to try reading len bytes. Stop when timeout is reached.
    static int tls_read_timeout(void *ctx, uint8_t *buf, size_t len, uint32_t timeout);
    /// Use TLSPSKConnection obejct in ctx to send len bytes.
    static int tls_write(void *ctx, const uint8_t *buf, size_t len);
    /// send size bytes over Client connection (should be encrypted)
    size_t writeraw(const uint8_t *buf, size_t size);
    /// read size bytes into buf (encrypted) data to pass to TLS decryption
    int readraw(uint8_t *buf, size_t size, uint32_t timeout_ms);

    /// underlying connection object
    Client &client;

    /// write at least some bytes
    int tls_write_some(const unsigned char *buf, size_t len);

    /// set up the environment for ssl connection (entropy, rngs, config, ciphers, keys)
    int setup_ssl(string_t pers, string_t psk_id, cbuf_t psk);
    /// make connection between actual socket and ssl machinery, perform handshake with peer
    int ssl_handshake();
};

#endif //TLSPSK_H_INCLUDED

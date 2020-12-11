#include <wificlientpsk.h>

#include <ArduinoLog.h>

#include <mbedtls/error.h>

namespace
{
    std::string mbedtls_error_msg(const int errnum)
    {
        constexpr size_t len = 128;
        char msg_buf[len];

        mbedtls_strerror(errnum, msg_buf, len);
        return std::string(msg_buf);
    }

    int tls_read_timeout(void *ctx, uint8_t *buf, size_t len, uint32_t timeout)
    {
        TLSPSKConnection *cl = reinterpret_cast<TLSPSKConnection *>(ctx);
        return cl->readraw(buf, len, timeout);
    }

    int tls_write(void *ctx, const uint8_t *buf, size_t len)
    {
        TLSPSKConnection *cl = reinterpret_cast<TLSPSKConnection *>(ctx);
        return cl->writeraw(buf, len);
    }

}; // namespace

TLSPSKConnection::TLSPSKConnection(
    Client &_client, const std::string &_psk_id, const psk_t &_psk, const std::string &_pers) : client(_client), pers{_pers}, psk_id{_psk_id}, m_psk(_psk)
{
    if (setup_ssl() != 0)
    {
        Log.fatal("Could not set up SSL!");
    }
}

size_t TLSPSKConnection::write(const uint8_t *buf, size_t size)
{
    const auto r = mbedtls_ssl_write(&ssl.m_ssl, buf, size);
    Log.verbose("Wrote %d bytes clear text", r);
    return r;
}

int TLSPSKConnection::read(uint8_t *buf, size_t size)
{
    const auto r = mbedtls_ssl_read(&ssl.m_ssl, buf, size);
    if (r > 0)
    {
        Log.verbose("Read %d bytes clear text.", r);
    }
    else
    {
        Log.warning("Read returned error: %s", mbedtls_error_msg(r).c_str());
    }
    return r;
}

size_t TLSPSKConnection::writeraw(const uint8_t *buf, size_t size)
{
    const auto r = client.write(buf, size);
    return r;
}

int TLSPSKConnection::readraw(uint8_t *buf, size_t size, uint32_t timeout_ms)
{
    // Log.verbose("read timeout: %d ms", timeout_ms);
    const auto begin = millis();
    while (!client.available() && client.connected())
    {
        const auto waiting_time = millis() - begin;
        if ((timeout_ms != 0) && (waiting_time > timeout_ms))
        {
            // timeout
            Log.notice("SSL read timeout");
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
        // waiting with implicit background processing
        yield();
    }

    const auto r = client.read(buf, size);
    return r;
}

int TLSPSKConnection::ssl_handshake()
{
    // Log.verbose("Attempting Handshake");
    auto ret = -1;
    do
    {
        ret = mbedtls_ssl_handshake(&ssl.m_ssl);
    } while ((ret == MBEDTLS_ERR_SSL_WANT_READ) ||
             (ret == MBEDTLS_ERR_SSL_WANT_WRITE));

    if (ret < 0)
    {
        // something went wrong
        Log.error(("In SSL handshake: " + mbedtls_error_msg(ret)).c_str());
    }

    return ret;
}

bool TLSPSKConnection::available()
{
    return (client.available() || (mbedtls_ssl_get_bytes_avail(&ssl.m_ssl)));
}

int TLSPSKConnection::connect()
{
    // we are TCP connected
    if (!client.connected())
    {
        Log.error("TLS connection needs a TCP connection first.");
        return -1;
    }

    // hook up read / write functions
    mbedtls_ssl_set_bio(&ssl.m_ssl, (void *)this, tls_write, NULL, tls_read_timeout);
    Log.verbose("set BIO");
    // reset session here, as we may have a stall session when the other side has reset and we are reconnecting.
    mbedtls_ssl_session_reset(&ssl.m_ssl);
    Log.verbose("Reset SSL session");

    if (ssl_handshake() != 0)
    {
        Log.error("SSL Handshake failed.");
        client.stop();

        return 0;
    }

    // 1 means successfully connected
    return 1;
}

int TLSPSKConnection::setup_ssl()
{
    {
        const auto r = mbedtls_ctr_drbg_seed(&ctr_drbg.m_ctr_drbg, mbedtls_entropy_func, &entropy.m_entropy,
                                             reinterpret_cast<const unsigned char *>(pers.c_str()), pers.length());
        if (r != 0)
        {
            Log.error(("Could not set up ctr drbg seed: " + mbedtls_error_msg(r)).c_str());
            return r;
        }
    }
    {
        const auto r = mbedtls_ssl_config_defaults(&conf.m_config,
                                                   MBEDTLS_SSL_IS_CLIENT,
                                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                                   MBEDTLS_SSL_PRESET_DEFAULT);
        if (r != 0)
        {
            Log.error(("Could not set up ssl config defaults: " + mbedtls_error_msg(r)).c_str());
            return r;
        }
    }

    mbedtls_ssl_conf_rng(&conf.m_config, mbedtls_ctr_drbg_random, &ctr_drbg);

    {
        Log.verbose("size of psk: %d", sizeof(m_psk));
        const auto r = mbedtls_ssl_conf_psk(&conf.m_config, m_psk.data(), sizeof(m_psk),
                                            reinterpret_cast<const unsigned char *>(psk_id.c_str()), psk_id.length());
        if (r != 0)
        {
            Log.error(("Could not configure psk: " + mbedtls_error_msg(r)).c_str());
            return r;
        }
    }

    mbedtls_ssl_conf_read_timeout(&conf.m_config, ssl_timeout);

    {
        const auto r = mbedtls_ssl_setup(&ssl.m_ssl, &conf.m_config);
        if (r != 0)
        {
            Log.error(("Could not setup ssl: " + mbedtls_error_msg(r)).c_str());
            return r;
        }
    }
    return 0;
}

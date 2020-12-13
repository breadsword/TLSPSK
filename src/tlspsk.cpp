#include <tlspsk.h>

#include <Arduino.h> // for millis() and yield()
#include <mbedtls/error.h>

std::string TLSPSKConnection::error_message(const int errnum)
{
    constexpr size_t len = 128;
    char msg_buf[len];

    mbedtls_strerror(errnum, msg_buf, len);
    return std::string(msg_buf);
}

int TLSPSKConnection::last_error() const
{
    return m_last_error;
}

TLSPSKConnection::TLSPSKConnection(
    Client &_client, const std::string _psk_id, cbuf_t _psk, const std::string _pers) : m_last_error{0}, client(_client)
{
    setup_ssl(_pers, _psk_id, _psk);
}

ssize_t TLSPSKConnection::write(cbuf_t buf)
{
    return write(buf.data(), buf.size_bytes());
}

ssize_t TLSPSKConnection::write(const uint8_t *buf, size_t size)
{
    const auto r = mbedtls_ssl_write(&ssl.m_ssl, buf, size);
    if (r < 0)
    {
        m_last_error = r;
    }
    return r;
}

ssize_t TLSPSKConnection::read(buf_t b)
{
    return read(b.data(), b.size_bytes());
}

ssize_t TLSPSKConnection::read(uint8_t *buf, size_t size)
{
    const auto r = mbedtls_ssl_read(&ssl.m_ssl, buf, size);
    if (r < 0)
    {
        m_last_error = r;
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
            m_last_error = MBEDTLS_ERR_SSL_TIMEOUT;
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
    auto ret = -1;
    do
    {
        ret = mbedtls_ssl_handshake(&ssl.m_ssl);
    } while ((ret == MBEDTLS_ERR_SSL_WANT_READ) ||
             (ret == MBEDTLS_ERR_SSL_WANT_WRITE));

    if (ret < 0)
    {
        m_last_error = ret;
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
        m_last_error = MBEDTLS_ERR_SSL_CONN_EOF;
        return -1;
    }

    // hook up read / write functions
    mbedtls_ssl_set_bio(&ssl.m_ssl, (void *)this, TLSPSKConnection::tls_write, NULL, TLSPSKConnection::tls_read_timeout);
    // reset session here, as we may have a stall session when the other side has reset and we are reconnecting.
    mbedtls_ssl_session_reset(&ssl.m_ssl);

    if (const auto r = ssl_handshake() < 0)
    {
        client.stop();
        return r;
    }

    // 1 means successfully connected
    return 1;
}

int TLSPSKConnection::tls_read_timeout(void *ctx, uint8_t *buf, size_t len, uint32_t timeout)
{
    TLSPSKConnection *cl = reinterpret_cast<TLSPSKConnection *>(ctx);
    return cl->readraw(buf, len, timeout);
}

int TLSPSKConnection::tls_write(void *ctx, const uint8_t *buf, size_t len)
{
    TLSPSKConnection *cl = reinterpret_cast<TLSPSKConnection *>(ctx);
    return cl->writeraw(buf, len);
}

int TLSPSKConnection::setup_ssl(string_t pers, string_t psk_id, cbuf_t psk)
{
    {
        const auto r = mbedtls_ctr_drbg_seed(&ctr_drbg.m_ctr_drbg, mbedtls_entropy_func, &entropy.m_entropy,
                                             reinterpret_cast<const unsigned char *>(pers.data()), pers.size_bytes());
        if (r != 0)
        {
            m_last_error = r;
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
            m_last_error = r;
            return r;
        }
    }

    mbedtls_ssl_conf_rng(&conf.m_config, mbedtls_ctr_drbg_random, &ctr_drbg);

    {
        const auto r = mbedtls_ssl_conf_psk(&conf.m_config, psk.data(), psk.size_bytes(),
                                            reinterpret_cast<const unsigned char *>(psk_id.data()), psk_id.size_bytes());
        if (r != 0)
        {
            m_last_error = r;
            return r;
        }
    }

    mbedtls_ssl_conf_read_timeout(&conf.m_config, ssl_timeout);

    {
        const auto r = mbedtls_ssl_setup(&ssl.m_ssl, &conf.m_config);
        if (r != 0)
        {
            m_last_error = r;
            return r;
        }
    }
    return 0;
}

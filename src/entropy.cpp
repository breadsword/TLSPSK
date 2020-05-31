#include <mbedtls/entropy.h>
#include <ArduinoLog.h>

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
extern "C"
{

    //alternative entropy generation function for mbedtls
    int mbedtls_hardware_poll(void *,
                              unsigned char *output, size_t len, size_t *olen)
    {
        Log.verbose("mbedtls_hardware_poll called. len: %d", len);
        // gather random numbers in 32 bits
        long l_r = 0;
        // give a byte-wise access to the location of the random number
        const unsigned char *v_r = reinterpret_cast<const unsigned char *>(&l_r);

        // copy byte-wise, get random value every 4 bytes
        for (size_t i = 0; i < len; ++i)
        {
            if ((i % 4) == 0)
            {
                l_r = secureRandom(ULONG_MAX);
            }
            output[len] = v_r[i % 4];
        }
        if (olen)
        {
            *olen = len;
        }

        Log.verbose("Provided %d bytes of entropy", len);

        return 0;
    }
}
#endif

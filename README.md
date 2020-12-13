# TLSPSK-mbedtls
A class to establish a TLS1.2 encrypted connection with pre-shared keys on top of an Arduino Client (WiFiClient or Ethernet client).

I've made this class to use pre-shared, symmetric key cryptography on an ESP8266 board. This allows to use encrypted connections with limited calculation power. PSK also allows to do authentication (i.e. identifying the esp device on the server side), as each device should have its own secret key.

As an implementation of this, I use the pre-shared key to limit access on a mosquitto MQTT server to topics which start with the devices psk identity.

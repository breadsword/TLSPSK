#include <Arduino.h>

#include <WiFiManager.h>

#include <ArduinoLog.h>
#include "tlspsk.h"

/*
  This will establish a connection to a remote host and run an SSL handshake using PSK.
  It then will try to exchange messages with the remote peer.

  The remote side can be set up using openssl:
  openssl s_server -nocert -psk 000102030405060708 -psk_identity " psk_test" -accept 27549

  Please configure your server hostname below either as DNS name or as IP address.

*/
constexpr uint8_t psk_secret[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
constexpr char psk_identity[] = "psk_test";

constexpr char message[] = "Hello, this is a message with some characters.\n";
const uint8_t *bmsg = reinterpret_cast<const uint8_t *const>(message);
constexpr auto msglen = sizeof(message);

constexpr auto BAUDRATE = 115200;
constexpr char server[] = "192.168.188.22"/* "your server here" */;
constexpr uint16_t port = 27549;

WiFiClient wifi;
TLSPSKConnection tls{wifi, psk_identity, psk_secret};

void printTimestamp(Print *_logOutput)
{
  static char timestamp[8 + 1];
  sprintf(timestamp, "%8lu", millis());
  _logOutput->print(timestamp);
}

void printNewline(Print *_logOutput)
{
  _logOutput->print('\n');
}

void setup_log(Print *output)
{
  Log.begin(LOG_LEVEL_VERBOSE, output);

  Log.setPrefix(printTimestamp);
  Log.setSuffix(printNewline);

  Log.notice("\n\n");
  Log.notice("**************");
}

void setup()
{
  Serial.begin(BAUDRATE);
  setup_log(&Serial);
  // initialize wifi
  WiFiManager manager;
  manager.autoConnect("testhostAP");
}

void loop()
{
  // put your main code here, to run repeatedly:
  if (wifi.connected())
  {
    auto bytes_written = tls.write(bmsg, msglen);
    Log.notice("Wrote %d bytes", bytes_written);

    while (tls.available())
    {
      constexpr size_t buflen = 512;
      unsigned char recv_buf[buflen + 1] = {0};
      const auto bytes_read = tls.read(recv_buf, buflen);
      if (bytes_read > 0)
      {
        Log.notice("Received %d bytes", bytes_read);
        Log.verbose("content: '%s'", recv_buf);
      }
      else
      {
        Log.error("Error when reading");
      }
    }
  }
  else
  {
    Log.notice("WiFiClient not connected. Trying to reconnect");
    const auto r = wifi.connect(server, port);
    if (r != 1)
    {
      Log.notice("TCP connect failed");
    }
    else
    {
      Log.notice("TCP connected");
      const auto r_tls = tls.connect();
      if (r_tls < 0)
      {
        Log.error("SLL handshake failed: %s", tls.error_message(tls.last_error()).c_str());
        wifi.stop();
      }

      Log.notice("SSL connection established.");
      // return directly and send without delay
      return;
    }
  }
  delay(2000);
}

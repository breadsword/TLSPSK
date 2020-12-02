#include <Arduino.h>

#include <WiFiManager.h>

#include "loghelpers.h"
#include <ArduinoLog.h>
#include "wificlientpsk.h"

constexpr char message[] = "Hello, this is a message with some characters.\n";
const uint8_t *bmsg = reinterpret_cast<const uint8_t *const>(message);
constexpr auto msglen = sizeof(message);

constexpr auto BAUDRATE = 115200;
constexpr char server[] = "Andreas-MBP.fritz.box";
constexpr uint16_t port = 27549;

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
  static WiFiPSKClient espClient{"test_id", {0, 1, 2, 3, 4, 5, 6, 7, 8}, "wemos_psk_test"};
  // put your main code here, to run repeatedly:

  if (espClient.connected())
  {
    auto bytes_written = espClient.write(bmsg, msglen);
    Log.notice("Wrote %d bytes", bytes_written);

    constexpr size_t buflen = 512;
    unsigned char recv_buf[buflen + 1] = {0};
    const auto bytes_read = espClient.read(recv_buf, buflen);
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
  else
  {
    Log.notice("WiFiClient not connected. Trying to reconnect");
    // create connection with WiFiClient
    const auto r = espClient.connect(server, port);
    if (r)
    {
      Log.notice("connected");
    }
    else
    {
      Log.notice("connect failed");
    }
  }
  delay(2000);
}

#include "loghelpers.h"
#include "ArduinoLog.h"

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

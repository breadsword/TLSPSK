#ifndef LOGHELPERS_HPP_INCLUDED
#define LOGHELPERS_HPP_INCLUDED

// use according to examples from https://github.com/thijse/Arduino-Log

class Print;
void printTimestamp(Print* _logOutput);
void printNewline(Print* _logOutput);

void setup_log(Print *output);


#endif //LOGHELPERS_HPP_INCLUDED

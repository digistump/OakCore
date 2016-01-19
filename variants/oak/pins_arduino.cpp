typedef unsigned short uint8_t;
#include "pins_arduino.h"

                              ///0, 1, 2, 3, 4, 5, 6,  7,  8,  9,  10, 11
unsigned short esp8266_pinToGpio[12] = {2, 5, 0, 3, 1, 4, 15, 13, 12, 14, 16, 17};
unsigned short esp8266_gpioToPin[18] = {2, 4, 0, 3, 5, 1, 255, 255, 255, 255, 255, 255, 8, 7, 9, 6, 10, 11};

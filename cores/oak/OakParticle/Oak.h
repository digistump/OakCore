#ifndef Oak_h
#define Oak_h

#include "Arduino.h"
class OakClass {
public:
	void rebootToUser(void);
	void rebootToConfig(void);
	void rebootToFallbackUpdater(void);
	bool checkROMImage(uint8_t rom_number);
	String infoResponse(void);
	String configureApFromJSON(String json);
	String setConfigFromJSON(String json);
};

extern OakClass Oak;

#endif // Oak_h

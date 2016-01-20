#ifndef Oak_h
#define Oak_h

#include "Arduino.h"
class OakClass {


public:
	OakClass(System_Mode_TypeDef mode = DEFAULT_MODE) {
		OakClass::SystemMode(mode);
	}
	void rebootToUser(void);
	void rebootToConfig(void);
	void rebootToFallbackUpdater(void);
	bool checkRomImage(uint8_t rom_number);
	uint8_t currentRom(void);
	uint8_t configRom(void);
	uint8_t userRom(void);
	uint8_t updateRom(void);
	String infoResponse(void);
	String configureApFromJSON(String json);
	String setConfigFromJSON(String json);
	bool flashEraseSector(uint32_t sector);
	void SystemMode(System_Mode_TypeDef mode);
};

extern OakClass Oak;
extern OakClass System;

#define SYSTEM_MODE(mode)  OakClass set_system_mode(mode);

#endif // Oak_h

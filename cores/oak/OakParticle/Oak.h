#ifndef Oak_h
#define Oak_h

#include "Arduino.h"
#include "particle_globals.h"
class OakClass {


public:
	OakClass(System_Mode_TypeDef mode = DEFAULT_MODE) {
		OakClass::SystemMode(mode);
	}
	uint8_t getEmptyRom(void);
	bool connect(void);
	bool connected(void);
	bool waitForConnection(void);
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
	System_Mode_TypeDef SystemMode(void);
	void SystemMode(System_Mode_TypeDef mode);
};

extern OakClass Oak;
extern OakClass System;

#define SYSTEM_MODE(mode)  OakClass set_system_mode(mode);

#endif // Oak_h


#include "Oak.h"
#include "particle_core.h"

using namespace particle_core;



void OakClass::rebootToUser(void) { 
	rebootToUser(); 
}
void OakClass::rebootToConfig(void) { 
	rebootToConfig(); 
}
void OakClass::rebootToFallbackUpdater(void) { 
	rebootToFallbackUpdater(); 
}
bool OakClass::checkRomImage(uint8_t rom_number) { 
	return check_image(rom_number);
}

String OakClass::infoResponse(void){
	return infoResponse();
}

String OakClass::setConfigFromJSON(String json){
	return setConfigFromJSON(json);
}

String OakClass::configureApFromJSON(String json){
	return configureApFromJSON(json);
}

void OakClass::SystemMode(System_Mode_TypeDef mode){
	set_system_mode(mode);
}

bool OakClass::flashEraseSector(uint32_t sector){
	flashEraseSector(sector);
}
uint8_t OakClass::currentRom(void){
	return currentRom();
}
uint8_t OakClass::configRom(void){
	return configRom();
}
uint8_t OakClass::userRom(void){
	return userRom();
}
uint8_t OakClass::updateRom(void){
	return updateRom();
}

OakClass Oak;

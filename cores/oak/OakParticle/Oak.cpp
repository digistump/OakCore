
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
bool OakClass::checkROMImage(uint8_t rom_number) { 
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

OakClass Oak;

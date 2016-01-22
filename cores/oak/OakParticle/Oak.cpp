
#include "Oak.h"
#include "particle_core.h"

using namespace particle_core;

bool OakClass::connected(void) { 
	return wifiConnected(); 
}
bool OakClass::connect(void) { 
	return wifiConnect(); 
}
bool OakClass::waitForConnection(void) { 
	return wifiWaitForConnection(); 
}
void OakClass::rebootToUser(void) { 
	reboot_to_user(); 
}
void OakClass::rebootToConfig(void) { 
	reboot_to_config(); 
}
uint8_t OakClass::getEmptyRom(void) { 
	return getOTAFlashSlot(); 
}
void OakClass::rebootToFallbackUpdater(void) { 
	reboot_to_fallback_updater(); 
}
bool OakClass::checkRomImage(uint8_t rom_number) { 
	return check_image(rom_number);
}

String OakClass::infoResponse(void){
	return info_response();
}

String OakClass::setConfigFromJSON(String json){
	return set_config_from_JSON(json);
}

String OakClass::configureApFromJSON(String json){
	return configure_ap_from_JSON(json);
}

System_Mode_TypeDef OakClass::SystemMode(void){
	return get_system_mode();
}

void OakClass::SystemMode(System_Mode_TypeDef mode){
	set_system_mode(mode);
}

bool OakClass::flashEraseSector(uint32_t sector){
	flash_erase_sector(sector);
}
uint8_t OakClass::currentRom(void){
	return current_rom();
}
uint8_t OakClass::configRom(void){
	return config_rom();
}
uint8_t OakClass::userRom(void){
	return user_rom();
}
uint8_t OakClass::updateRom(void){
	return update_rom();
}

OakClass Oak;

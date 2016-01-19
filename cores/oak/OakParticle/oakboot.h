#ifndef __OAKBOOT_H__
#define __OAKBOOT_H__

//////////////////////////////////////////////////
// OakBoot by Erik Kettenburg/Digistump
// Based on rBoot open source boot loader for ESP8266.
// Copyright 2015 Richard A Burton
// richardaburton@gmail.com
// See license.txt for license terms.
//////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

// uncomment to use only c code
// if you aren't using gcc you may need to do this
//#define BOOT_NO_ASM


#define CHKSUM_INIT 0xef

#ifndef MAX_ROM_SIZE //this becomes variable in the new scheme
  #define MAX_ROM_SIZE (0x100000-0x2000)
#endif
#define BOOT_CONFIG_SIZE 92
#define SECTOR_SIZE 0x1000
#define BOOT_KEY_SECTOR 513
#define BOOT_CONFIG_SECTOR 1
#define BOOT_BACKUP_CONFIG_SECTOR 257

#define BOOT_CONFIG_MAGIC 0xe1
#define BOOT_CONFIG_VERSION 0x01

#define MODE_STANDARD 0x00
#define MODE_GPIO_ROM 0x01

// boot config structure
// rom addresses must be multiples of 0x1000 (flash sector aligned)
// without BOOT_BIG_FLASH only the first 8Mbit of the chip will be memory mapped
// so rom slots containing .irom0.text sections must remain below 0x100000
// slots beyond this will only be accessible via spi read calls, so
// use these for stored resources, not code
// with BOOT_BIG_FLASH the flash will be mapped in chunks of 8MBit, so roms can
// be anywhere, but must not straddle two 8MBit blocks
#define UPDATE_ROM 0
#define CONFIG_ROM 1
#define PROGRAM_ROM 2

typedef struct {
  uint8 magic;       // our magic
  uint8 version;       // config struct version
  uint8 mode;        // boot loader mode
  uint8 current_rom;     // currently running rom
  uint8 program_rom;    // currently selected program rom
  uint8 update_rom;     // currently selected factory rom
  uint8 config_rom;     // currently selected factory rom
  //factory holds WiFi setup stuff, update stuff, tinker app - which part it triggers is based on reboot_reason
  //on update don't change reboot reason back to 0 until update is success, then it will jump back to try to get update automatically
  uint8 count;       // number of roms in use

  uint32 roms[16]; // flash addresses of the roms - extra spot if needed 
    uint8 update;   // force factory for one cycle
  uint8 config;   // force factory for one cycle
    uint8 failures;     // consecutive failures until factory
  uint8 failures_allowed; //failures until recovery
  uint8 factory_reason;   // NOT IN USE - number of roms in use
  uint8 reboot_reason; //last time bootloader entered via gpio
  uint8 led_off; //turn failure led off
  uint8 first_boot; //turn failure led off
  uint8 reset_write_skip; //turn failure led off
  uint8 reinit_config; //turn failure led off
  uint8 bootkey_disable; //turn failure led off
  uint8 serial_mode; //turn failure led off
  uint8 rom_on_swdt; //turn failure led off
  uint8 rom_on_hwdt; //turn failure led off
  uint8 rom_on_exception; //turn failure led off
  uint8 rom_on_gpio; //turn failure led off
  uint8 rom_on_invalid; //turn failure led off
  uint8 rom_on_reinit; //turn failure led off
  uint8 padding; //turn failure led off
  uint8 chksum; //checksum for sector
} oakboot_config; 

/*
 typedef struct {
  //can cut off here if needed
  char device_id[25];     //device id in hex
  char claim_code[65];   // server public key
  uint8 claimed;   // server public key
  uint8 device_private_key[1216];  // device private key
  uint8 device_public_key[384];   // device public key
  uint8 server_public_key[768]; //also contains the server address at offset 384
  uint8 server_address_type;   //domain or ip of cloud server
  uint8 server_address_length;   //domain or ip of cloud server
  char server_address_domain[254];   //domain or ip of cloud server
  uint8 padding;
  uint32 server_address_ip;   //[4]//domain or ip of cloud server
  unsigned short firmware_version;  
  unsigned short system_version;     //
  char version_string[33];    //
  uint8 reserved_flags[32];    //
  uint8 reserved1[32];
  uint8 product_store[24];    
  uint8 padding2[3];
  int32 third_party_id;    //
  char third_party_data[256];     //
  uint8 reserved2[960]; 
  uint8 end[0]; 
} oak_config; */

typedef struct { //can expand all we want because we only read, we don't write in the bootloader
  uint8 mode; //serial, local ota, etc - see comments
  uint8 reset; //force reinit the config
  uint8 gpio; //force allow gpio 16 high to bootloader  
} oakboot_bootkey;

#ifdef __cplusplus
}
#endif

#endif

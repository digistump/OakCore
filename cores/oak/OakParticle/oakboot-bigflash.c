//////////////////////////////////////////////////
// OakBoot by Erik Kettenburg/Digistump
// Based on rBoot open source boot loader for ESP8266.
// Copyright 2015 Richard A Burton
// richardaburton@gmail.com
// See license.txt for license terms.
//////////////////////////////////////////////////

typedef int int32;
typedef unsigned int uint32;
typedef unsigned char uint8;

#include "oakboot.h"

#define IRAM_ATTR __attribute__((section(".iram.text")))


#ifdef __cplusplus
extern "C" {
#endif

extern void Cache_Read_Disable();
extern uint32 SPIRead(uint32, void*, uint32);
extern void ets_printf(const char*, ...);
extern void Cache_Read_Enable(uint32, uint32, uint32);

uint8 oakboot_mmap_1 = 0xff;
uint8 oakboot_mmap_2 = 0xff;

// this function must remain in iram
void IRAM_ATTR Cache_Read_Enable_New() {
#pragma message "CACHE READ COMPILED"
  
  if (oakboot_mmap_1 == 0xff) {
    uint32 addr;
    oakboot_config conf;
    
    Cache_Read_Disable();
    
    SPIRead(BOOT_CONFIG_SECTOR * SECTOR_SIZE, &conf, sizeof(oakboot_config));
    //uint8 temp;
    //SPIRead(256 * SECTOR_SIZE, &temp, 1);
    ///ets_printf("t %d\r\n", temp);

    /*if(conf.current_rom<8)
      oakboot_mmap_2 = 0;
    else
      oakboot_mmap_2=1;

    if(conf.current_rom<4 || (conf.current_rom>7 && conf.current_rom<12) )
      oakboot_mmap_1 = 0;
    else
      oakboot_mmap_1=1;*/

    //if(conf.current_rom<2)
    //  oakboot_mmap_1 = 0;
    //else
    //  oakboot_mmap_1 = 1;
    
    
    addr = conf.roms[conf.current_rom];
    addr /= 0x100000;
    
    oakboot_mmap_2 = addr / 2;
    oakboot_mmap_1 = addr % 2;
    
    //ets_printf("mmap %d,%d,1\r\n", oakboot_mmap_1, oakboot_mmap_2);
  }
  
  Cache_Read_Enable(oakboot_mmap_1, oakboot_mmap_2, 1);
}

#ifdef __cplusplus
}
#endif



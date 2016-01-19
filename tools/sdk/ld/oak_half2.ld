/* Flash Split for 4M chips */
/* sketch 1019KB */
/* empty  2048KB */
/* spiffs 1004KB */
/* eeprom 20KB */

MEMORY
{
  dport0_0_seg :                        org = 0x3FF00000, len = 0x10
  dram0_0_seg :                         org = 0x3FFE8000, len = 0x14000
  iram1_0_seg :                         org = 0x40100000, len = 0x8000
  irom0_0_seg :                         org = 0x40281010, len = 0x7eff0
}

PROVIDE ( _SPIFFS_start = 0x40500000 );
PROVIDE ( _SPIFFS_end = 0x405FB000 );
PROVIDE ( _SPIFFS_page = 0x100 );
PROVIDE ( _SPIFFS_block = 0x2000 );
PROVIDE ( ets_wdt_disable = 0x400030f0 );
PROVIDE ( ets_wdt_enable = 0x40002fa0 );
PROVIDE ( ets_wdt_get_mode = 0x40002f34 );
PROVIDE ( ets_wdt_init = 0x40003170 );
PROVIDE ( ets_wdt_restore = 0x40003158 );
INCLUDE "../ld/eagle.app.v6.common.ld"

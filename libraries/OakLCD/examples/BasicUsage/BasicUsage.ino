/*                          
 * Most I2C LCDs require 5V - generally you must use a level shifter to use with the Oak, or at the very least power the LCD from 5V and risk burning out the i/o pins
 */

//#define DEBUG
#include <Wire.h>                  // I2C Master lib for ATTinys which use USI - comment this out to use with standard arduinos
#include <LiquidCrystal_I2C.h>          // for LCD w/ GPIO MODIFIED for the ATtiny85

#define GPIO_ADDR     0x27             // (PCA8574A A0-A2 @5V) typ. A0-A3 Gnd 0x20 / 0x38 for A - 0x27 is the address of the Digispark LCD modules.


LiquidCrystal_I2C lcd(GPIO_ADDR,16,2);  // set address & 16 chars / 2 lines


void setup(){
  Serial.begin(115200);

  Wire.begin();                    // initialize I2C lib - comment this out to use with standard arduinos
  lcd.init();                           // initialize the lcd 
  lcd.backlight();                      // Print a message to the LCD.
  lcd.print("Oak!");
}


void loop(){

}

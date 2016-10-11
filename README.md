## You must update your Arduino Oak package to 1.0.0+ via the boards manager! 

**If you previously used an earlier Beta please do a factory reset here: http://github.com/digistump/OakRestore**

**MAKE SURE YOU USE THE LATEST OakSoftAP - force a browser refresh before using**

**HOW TO INSTALL AND USE THIS:** http://digistump.com/wiki/oak/tutorials/arduino
**TROUBLESHOOTING:** http://digistump.com/wiki/oak/tutorials/troubleshooting

**PLEASE GO TO THE FORUMS FOR HELP:** http://digistump.com/board

**PLEASE FILE ISSUES FOR BUGS:** with as much detail as possible!




**Working Particle APIs:**

- Particle.variable()
- Particle.function()
- Particle.publish()
- Particle.subscribe()
- Particle.unsubscribe()
- Particle.connect()
- Particle.disconnect()
- Particle.connected()
- Particle.process()
- Particle.syncTime() - though time is not yet connected to anything

Particle docs here: https://docs.particle.io/reference/firmware/photon/

The rest of the Particle APIs are not connected right now. But all of the ESP8266 APIs are.

Be advised that some ESP8266 libraries that are included may break it, and none of the libraries have been fully tested against this release yet.

ESP8266 docs here: http://esp8266.github.io/Arduino/versions/2.0.0/doc/libraries.html

**Other useful info:**

- Oak.rebootToConfig() will get you into WiFi Config setup mode.
  - If you can't boot into that then pull Pin 1 to GND and it power cycle and you will boot to that.
  - Next release will have an option to boot there automatically if there the WiFi can't connect.
  - It will also boot to a safe mode if there is a timeout (do to a while loop that doesn't call Particle.process()) or a exception (memory overflow, etc) - in that mode it will just wait for an update. If you power cycle it will go back to the user program.
- DO NOT mess with the flash read/write/erase functions - erase the wrong sector and it will brick the unit.
- Future system updates will come automatically when you upload a new sketch.
- Have fun! Much more to come! 

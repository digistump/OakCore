## You must update your Arduino Oak package to 0.9.3 via the boards manager! 
**If you previously used an earlier Beta please do a factory reset here: http://github.com/digistump/OakRestore**

**MAKE SURE YOU USE THE LATEST OakSoftAP - force a browser refresh before using**

**HOW TO INSTALL AND USE THIS:** http://digistump.com/wiki/oak/tutorials/arduino
**TROUBLESHOOTING:** http://digistump.com/wiki/oak/tutorials/troubleshooting

**PLEASE FILE ISSUES FOR BUGS:** with as much detail as possible!

**Issues Fixed with this release:**

- Code examples and libraries for most shields
- Various small fixes (see github issue tracker for most)
- Change to a distinct blink pattern in config mode (3 blink bursts with 0.5 seconds between the bursts)
- More responsive during WiFi config changes
- Better connect/reconnect logic
- Various safeties against changing the WiFi config in sketch
- Particle.delay is no longer necessary - just use regular delay() - for very time sensitive things you can also use delay_internal()
- Change to Pin 0 held LOW at boot to enter config as a failsafe
- Servo library works - min/max defs fixed
- All Particle.variable types work


**Known Issues with this release:**

- OTA Updates are very slow! 2-3 minutes on average. When an OTA update is taking place the LED will blink somewhat erratically - one toggle per packet arriving. (This is Temporary - FastOTA will be turned on in a near future release)
- ~~You MUST use Particle.delay() in place of delay()~~ Now you must just use delay() like you do with normal Arduino sketched
- Initial connection before the user application starts is still a bit slow, but not horrible.
- Not tested exhaustively! May brick your unit, please don't try to break it, yet... unless you really want to.
- If you brick your unit you'll need a 3.3v serial adapter to revive it. (See https://github.com/digistump/OakRestore)
- Serial over the cloud is not fully working yet - a serial adapter on pins 3(RX) and 4(TX) can be a big help until that gets sorted in the next release or if you are debugging anything major, for now.

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
  - If you can't boot into that then pull Pin 10 to GND and it power cycle and you will boot to that.
  - Next release will have an option to boot there automatically if there the WiFi can't connect.
  - It will also boot to a safe mode if there is a timeout (do to a while loop that doesn't call Particle.process()) or a exception (memory overflow, etc) - in that mode it will just wait for an update. If you power cycle it will go back to the user program.
- DO NOT mess with the flash read/write/erase functions - erase the wrong sector and it will brick the unit.
- Future system updates will come automatically when you upload a new sketch.
- Have fun! Much more to come! 


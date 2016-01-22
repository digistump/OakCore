# OakCore - EARLY BETA RELEASE

**HOW TO INSTALL AND USE THIS:** http://digistump.com/wiki/oak/tutorials/arduino

**PLEASE FILE ISSUES FOR BUGS:** with as much detail as possible!

**Known Issues with this release:**

- OTA Updates are very slow! 2-3 minutes on average. When an OTA update is taking place the LED will blink somewhat erratically - one toggle per packet arriving. 
- You MUST use Particle.delay() in place of delay()
- Initial connection before the user application starts is still a bit slow, but not horrible.
- Not tested exhaustively! May brick your unit, please don't try to break it, yet... unless you really want to.
- If you brick your unit you'll need a 3.3v serial adapter to revive it. (And I need to write up a how to still!)
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


Special thanks for this release to my wife and daughter (who haven't seen much of me the last few weeks), the Particle (@spark) team, especially Dave, Zachary, Stephanie, and Zach - @povrazor, @DarkLotus, @danielmawhirter, @fri-sch, @DeuxVis, @TrueJournals on github (and anyone else we missed), and - most of all - all of our backers on Kickstarter and via Pre-order

# Ultimate Kit Mini-Tutorial: Reading a Potentiometer and Controlling an LED

## Parts List
- Oak microcontroller board
- Breadboard
- LED (any color)
- 220Ω resistor
- Potentiometer (10kΩ)
- Jumper wires

## Lesson Overview
In this lesson, you will learn how to read an analog sensor (a potentiometer) and use its value to control the brightness of an LED. This project introduces analog input and PWM output.

## What You Will Learn
- How to connect a potentiometer and LED to the Oak board
- How to read analog values from sensors
- How to control LED brightness using PWM

## How to Do It

### Hardware Setup
1. Connect the potentiometer's left pin to 3.3V on the Oak.
2. Connect the potentiometer's right pin to GND on the Oak.
3. Connect the potentiometer's middle pin (wiper) to analog pin A0 on the Oak.
4. Connect the LED's longer leg (anode) to digital pin D3 on the Oak.
5. Connect the LED's shorter leg (cathode) to one end of the 220Ω resistor.
6. Connect the other end of the resistor to the Oak's GND pin.
7. Use jumper wires to make the connections on the breadboard.

### Circuit Diagram
![Ultimate Kit Potentiometer and LED Circuit](https://digistump.com/wiki/oak/tutorials/images/ultimate_kit_pot_led.png)

### Example Code
```cpp
// Read potentiometer and control LED brightness

void setup() {
  pinMode(D3, OUTPUT); // Set pin D3 as an output for the LED
}

void loop() {
  int sensorValue = analogRead(A0); // Read the potentiometer value (0-1023)
  int brightness = map(sensorValue, 0, 1023, 0, 255); // Map to PWM range
  analogWrite(D3, brightness); // Set LED brightness
  delay(10); // Small delay for stability
}
```

### Explanation
- `analogRead(A0);` reads the voltage from the potentiometer.
- `map()` converts the 0-1023 sensor value to 0-255 PWM range.
- `analogWrite(D3, brightness);` sets the LED brightness using PWM.
- The loop continuously updates the LED brightness based on the potentiometer.

## What This Teaches
- How to read analog sensor inputs.
- How to use PWM to control LED brightness.
- Mapping sensor values to output ranges.

## Credits
Created by Atlas 4 for Digistump LLC.

For more tutorials, visit: [digistump.com/wiki/oak/tutorials](https://digistump.com/wiki/oak/tutorials)

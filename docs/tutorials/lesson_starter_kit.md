# Starter Kit Mini-Tutorial: Blinking an LED

## Parts List
- Oak microcontroller board
- Breadboard
- LED (any color)
- 220Ω resistor
- Jumper wires

## Lesson Overview
In this lesson, you will learn how to make an LED blink using your Oak Starter Kit. This simple project teaches you the basics of digital output and how to control hardware components with code.

## What You Will Learn
- How to connect an LED to the Oak board
- How to write a simple program to blink the LED
- Basic understanding of digital output pins

## How to Do It

### Hardware Setup
1. Connect the LED's longer leg (anode) to digital pin D2 on the Oak.
2. Connect the LED's shorter leg (cathode) to one end of the 220Ω resistor.
3. Connect the other end of the resistor to the Oak's GND pin.
4. Use jumper wires to make the connections on the breadboard.

### Circuit Diagram
![Starter Kit LED Blink Circuit](https://digistump.com/wiki/oak/tutorials/images/starter_kit_led_blink.png)

### Example Code
```cpp
// Blink an LED connected to pin D2

void setup() {
  pinMode(D2, OUTPUT); // Set pin D2 as an output
}

void loop() {
  digitalWrite(D2, HIGH); // Turn the LED on
  delay(500);             // Wait for 500 milliseconds
  digitalWrite(D2, LOW);  // Turn the LED off
  delay(500);             // Wait for 500 milliseconds
}
```

### Explanation
- `pinMode(D2, OUTPUT);` configures pin D2 to send voltage to the LED.
- `digitalWrite(D2, HIGH);` turns the LED on by sending voltage.
- `delay(500);` pauses the program for half a second.
- `digitalWrite(D2, LOW);` turns the LED off by stopping voltage.
- The loop repeats, causing the LED to blink.

## What This Teaches
- How to control hardware outputs with code.
- The concept of digital HIGH and LOW signals.
- Basic timing with delays.

## Credits
Created by Atlas 4 for Digistump LLC.

For more tutorials, visit: [digistump.com/wiki/oak/tutorials](https://digistump.com/wiki/oak/tutorials)

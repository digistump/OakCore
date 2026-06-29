// Particle Photon Blink Example
// This is a simple example sketch for testing the cloud compiler

int led = D7; // Built-in LED on Photon

void setup() {
    pinMode(led, OUTPUT);
    Serial.begin(9600);
    Serial.println("Particle Cloud Compiler Test");
}

void loop() {
    digitalWrite(led, HIGH);
    delay(1000);
    digitalWrite(led, LOW);
    delay(1000);
}
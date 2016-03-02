void setup() {
  // put your setup code here, to run once:
  botInit();
}
 
 
void loop() {
  // put your main code here, to run repeatedly:
  botForward(1023); //speed can be any value from 0 (stopped) to 1023 (full)
  delay(5000);
  botReverse(1023);
  delay(5000);
  botRight(1023);
  delay(5000);
  botHardRight(1023);
  delay(5000);
  botLeft(1023);
  delay(5000);
  botHardLeft(1023);
  delay(5000);
  botStop();
  delay(5000);
}
 
void botForward(int botSpeed){
 digitalWrite(2, HIGH); 
 digitalWrite(5, HIGH);
 analogWrite(0, 1023 - botSpeed);
 analogWrite(1, 1023 - botSpeed);
}
 
void botReverse(int botSpeed){
 digitalWrite(2, LOW); 
 digitalWrite(5, LOW);
 analogWrite(0, botSpeed);
 analogWrite(1, botSpeed);
}
 
void botRight(int botSpeed){
 digitalWrite(2, LOW); 
 digitalWrite(5, HIGH);
 analogWrite(0, 0);
 analogWrite(1, 1023 - botSpeed);
}
 
void botHardRight(int botSpeed){
 digitalWrite(2, LOW); 
 digitalWrite(5, HIGH);
 analogWrite(0, botSpeed);
 analogWrite(1, 1023 - botSpeed);
}
 
void botLeft(int botSpeed){
 digitalWrite(2, HIGH); 
 digitalWrite(5, LOW);
 analogWrite(0, 1023 - botSpeed);
 analogWrite(1, 0);
}
 
void botHardLeft(int botSpeed){
 digitalWrite(2, HIGH); 
 digitalWrite(5, LOW);
 analogWrite(0, 1023 - botSpeed);
 analogWrite(1, botSpeed);
}
 
void botStop(){
 digitalWrite(2,LOW); 
 digitalWrite(5,LOW);
 analogWrite(0,0);
 analogWrite(1,0);
}
 
void botInit(){
 pinMode(0,OUTPUT);
 pinMode(1,OUTPUT);
 pinMode(2,OUTPUT);
 pinMode(5,OUTPUT);
}

#include "particle_core.h"
#include "OakParticle.h"

using namespace particle_core;

CloudClass::CloudClass(){
    spark_initConfig(false);
}


template<typename T> bool CloudClass::variable(const char *varKey, const typename T::varref userVar, const T& userVarType)
{
    return CLOUD_FN(spark_variable(varKey, (const void*)userVar, T::value(), NULL), false);
}

bool CloudClass::variable(const char *varKey, const int32_t* userVar, const CloudVariableTypeInt& userVarType)
{
    return CLOUD_FN(spark_variable(varKey, (const void*)userVar, CloudVariableTypeInt::value(), NULL), false);
}

bool CloudClass::variable(const char *varKey, const uint32_t* userVar, const CloudVariableTypeInt& userVarType)
{
    return CLOUD_FN(spark_variable(varKey, (const void*)userVar, CloudVariableTypeInt::value(), NULL), false);
}

template<typename T>
bool CloudClass::variable(const T *varKey, const String *userVar, const CloudVariableTypeString& userVarType)
{
    spark_variable_t extra;
    extra.size = sizeof(extra);
    extra.update = update_string_variable;
    return CLOUD_FN(spark_variable(varKey, userVar, CloudVariableTypeString::value(), &extra), false);
}

bool CloudClass::function(const char *funcKey, user_function_int_str_t* func)
{
    return CLOUD_FN(register_function(call_raw_user_function, (void*)func, funcKey), false);
}

bool CloudClass::function(const char *funcKey, user_std_function_int_str_t func, void* reserved)
{
#ifdef SPARK_NO_CLOUD
    return false;
#else
    bool success = false;
    if (func) // if the call-wrapper has wrapped a callable object
    {
        auto wrapper = new user_std_function_int_str_t(func);
        if (wrapper) {
            success = register_function(call_std_user_function, wrapper, funcKey);
        }
    }
    return success;
#endif
}

template <typename T>
void CloudClass::function(const char *funcKey, int (T::*func)(String), T *instance) {
    using namespace std::placeholders;
    function(funcKey, std::bind(func, instance, _1));
}

bool CloudClass::publish(const char *eventName, Spark_Event_TypeDef eventType)
{
    return CLOUD_FN(spark_send_event(eventName, NULL, 60, eventType, NULL), false);
}

bool CloudClass::publish(const char *eventName, const char *eventData, Spark_Event_TypeDef eventType)
{
    return CLOUD_FN(spark_send_event(eventName, eventData, 60, eventType, NULL), false);
}

bool CloudClass::publish(const char *eventName, const char *eventData, int ttl, Spark_Event_TypeDef eventType)
{
    return CLOUD_FN(spark_send_event(eventName, eventData, ttl, eventType, NULL), false);
}

bool CloudClass::subscribe(const char *eventName, EventHandler handler, Spark_Subscription_Scope_TypeDef scope)
{
    return CLOUD_FN(spark_subscribe(eventName, handler, NULL, scope, NULL, NULL), false);
}

bool CloudClass::subscribe(const char *eventName, EventHandler handler, const char *deviceID)
{
    return CLOUD_FN(spark_subscribe(eventName, handler, NULL, MY_DEVICES, deviceID, NULL), false);
}

bool CloudClass::subscribe(const char *eventName, wiring_event_handler_t handler, Spark_Subscription_Scope_TypeDef scope)
{
    return subscribe_wiring(eventName, handler, scope);
}

bool CloudClass::subscribe(const char *eventName, wiring_event_handler_t handler, const char *deviceID)
{
    return subscribe_wiring(eventName, handler, MY_DEVICES, deviceID);
}

template <typename T>
bool CloudClass::subscribe(const char *eventName, void (T::*handler)(const char *, const char *), T *instance, Spark_Subscription_Scope_TypeDef scope)
{
    using namespace std::placeholders;
    return subscribe(eventName, std::bind(handler, instance, _1, _2), scope);
}

template <typename T>
bool CloudClass::subscribe(const char *eventName, void (T::*handler)(const char *, const char *), T *instance, const char *deviceID)
{
    using namespace std::placeholders;
    return subscribe(eventName, std::bind(handler, instance, _1, _2), deviceID);
}

void CloudClass::unsubscribe()
{
    CLOUD_FN(remove_event_handlers(NULL), (void)0);
}

bool CloudClass::syncTime(void)
{
    return CLOUD_FN(send_time_request(),false);
}

/*
    static void sleep(long seconds) __attribute__ ((deprecated("Please use System.sleep() instead.")))
    { SystemClass::sleep(seconds); }
    static void sleep(Spark_Sleep_TypeDef sleepMode, long seconds=0) __attribute__ ((deprecated("Please use System.sleep() instead.")))
    { SystemClass::sleep(sleepMode, seconds); }
    static void sleep(uint16_t wakeUpPin, InterruptMode edgeTriggerMode, long seconds=0) __attribute__ ((deprecated("Please use System.sleep() instead.")))
    { SystemClass::sleep(wakeUpPin, edgeTriggerMode, seconds); }
*/

void CloudClass::initialize(bool isSystem) { return spark_initConfig(isSystem); }
bool CloudClass::connected(void) { return spark_connected(); }
bool CloudClass::disconnected(void) { return !connected(); }
bool CloudClass::connect(bool internal) { return spark_auto_connect(internal); }
void CloudClass::disconnect(void) { spark_disconnect(); }
void CloudClass::process(void) { spark_process(false); }
void delay(unsigned long ms) { spark_delay(ms); }
void checkSafeMode(void) { 
    if(digitalRead(10) == HIGH){
        uint32_t startHold = millis();
        while(millis() - startHold < 100){
            if(digitalRead(10) == LOW)
                return;
        }
        reboot_to_config();
    } 
}
String CloudClass::deviceID(void) { return spark_deviceID(); }

//private:

//static bool register_function(cloud_function_t fn, void* data, const char* funcKey);
//static int call_raw_user_function(void* data, const char* param, void* reserved);
//static int call_std_user_function(void* data, const char* param, void* reserved);

//static void call_wiring_event_handler(const void* param, const char *event_name, const char *data);

bool CloudClass::subscribe_wiring(const char *eventName, wiring_event_handler_t handler, Spark_Subscription_Scope_TypeDef scope, const char *deviceID)
{
#ifdef SPARK_NO_CLOUD
    return false;
#else
    bool success = false;
    if (handler) // if the call-wrapper has wrapped a callable object
    {
        auto wrapper = new wiring_event_handler_t(handler);
        if (wrapper) {
            success = spark_subscribe(eventName, (EventHandler)call_wiring_event_handler, wrapper, scope, deviceID, NULL);
        }
    }
    return success;
#endif
}

const void* CloudClass::update_string_variable(const char* name, Spark_Data_TypeDef type, const void* var, void* reserved)
{
    const String* s = (const String*)var;
    return s->c_str();
}

void CloudClass::begin()
{
    spark_serial_begin();
}

size_t CloudClass::write(uint8_t b)
{
    return spark_serial_write(b);
}

int CloudClass::available()
{
    return spark_serial_available();
}

int CloudClass::read()
{
    spark_serial_read();
}

int CloudClass::peek()
{
    spark_serial_peek();
}

void CloudClass::flush()
{
    spark_serial_flush();
}

void CloudClass::end()
{
    spark_serial_end();
}

String CloudClass::pubKey(){
  return pub_key();
}

bool CloudClass::isClaimed(){
  return is_claimed();
}

bool CloudClass::provisionKeys(bool force){//(bool force){
   return provision_keys(force);
}

CloudClass Particle;

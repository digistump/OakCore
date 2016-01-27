#ifndef particle_core_h
#define particle_core_h

#include "particle.h"
#include "particle_globals.h"

namespace particle_core {

bool check_image(uint8_t rom_number);

void clear_factory_reason(void);
uint8_t read_factory_reason(void);
void init_bootloader_flags(void);
void set_bootloader_reason_write_skip(void);
void set_oakboot_defaults(uint8_t failure_rom);
	
typedef std::function<bool(const void*, SparkReturnType::Enum)> FunctionResultCallback;

int call_raw_user_function(void* data, const char* param, void* reserved);

int call_std_user_function(void* data, const char* param, void* reserved);

void call_wiring_event_handler(const void* handler_data, const char *event_name, const char *data);

bool spark_connected();

unsigned short next_message_id();

static uint8 calc_device_chksum(uint8 *start, uint8 *end);

void writeDeviceConfig();

uint8_t hex_nibble(unsigned char c);

size_t hex_decode(uint8_t* buf, size_t len, const char* hex);

bool IPAddressFromString(IPAddress &ipaddress, const char *address);

int rsa_random(void* p);

static char ascii_nibble(uint8_t nibble);

bool generatePrivateKey(uint8_t *keyBuffer);

// Returns bytes received or -1 on error
int blocking_send(const unsigned char *buf, int length);

// Returns bytes received or -1 on error
int receive(unsigned char *buf, int length);

// Returns bytes received or -1 on error
int blocking_receive(unsigned char *buf, int length);

int decrypt_rsa(const uint8_t* ciphertext, const uint8_t* private_key, uint8_t* plaintext, int plaintext_len);
int decrypt(char* plaintext, int max_plaintext_len, char* hex_encoded_ciphertext);

int set_key(const unsigned char *signed_encrypted_credentials);

void encrypt(unsigned char *buf, int length);

void ping(unsigned char *buf);

size_t wrap(unsigned char *buf, size_t msglen);


void hello(unsigned char *buf, bool newly_upgraded);


void variable_value(unsigned char *buf,
                                   unsigned char token,
                                   unsigned char message_id_msb,
                                   unsigned char message_id_lsb,
                                   bool return_value);

void variable_value(unsigned char *buf,
                                   unsigned char token,
                                   unsigned char message_id_msb,
                                   unsigned char message_id_lsb,
                                   int return_value);
                                   
void variable_value(unsigned char *buf,
                                   unsigned char token,
                                   unsigned char message_id_msb,
                                   unsigned char message_id_lsb,
                                   double return_value);

// Returns the length of the buffer to send
int variable_value(unsigned char *buf,
                                  unsigned char token,
                                  unsigned char message_id_msb,
                                  unsigned char message_id_lsb,
                                  const void *return_value,
                                  int length);

void set_time(uint32_t time);

uint32_t get_time();

void handle_time_response(uint32_t time);

int numUserFunctions(void);

const char* getUserFunctionKey(int function_index);

int numUserVariables(void);

const char* getUserVariableKey(int variable_index);

int userVarType(const char *varKey);

bool send_subscription(const char *event_name, const char *device_id);

bool send_subscription(const char *event_name,
                                      SubscriptionScope::Enum scope);

void send_subscriptions();
void spark_delay(uint32_t ms);

bool event_handler_exists(const char *event_name, EventHandler handler,
    void *handler_data, SubscriptionScope::Enum scope, const char* id);

bool add_event_handler(const char *event_name, EventHandler handler,
    void *handler_data, SubscriptionScope::Enum scope, const char* id);


const void *getUserVar(const char *varKey);

int userFuncSchedule(const char *funcKey, const char *paramString, FunctionResultCallback callback, void* reserved);

bool spark_auto_connect(bool internal);

SubscriptionScope::Enum convert(Spark_Subscription_Scope_TypeDef subscription_type);

bool register_event(const char* eventName, SubscriptionScope::Enum event_scope, const char* deviceID);

bool spark_subscribe(const char *eventName, EventHandler handler, void* handler_data,
        Spark_Subscription_Scope_TypeDef scope, const char* deviceID, void* reserved);


// Returns true on success, false on sending timeout or rate-limiting failure
bool send_event(const char *event_name, const char *data,
                               int ttl, EventType::Enum event_type);

bool spark_send_event(const char* name, const char* data, int ttl, Spark_Event_TypeDef eventType, void* reserved);

bool spark_variable(const char *varKey, const void *userVar, Spark_Data_TypeDef userVarType, spark_variable_t* extra);

void function_return(unsigned char *buf,
                                    unsigned char token,
                                    int return_value);


bool spark_function_internal(const cloud_function_descriptor* desc, void* reserved);

/**
 * This is the original released signature for firmware version 0 and needs to remain like this.
 * (The original returned void - we can safely change to bool.)
 */
bool spark_function(const char *funcKey, p_user_function_int_str_t pFunc, void* reserved);

bool register_function(cloud_function_t fn, void* data, const char* funcKey);

String buffer_to_string(const uint8_t *buf,size_t length);

int description(unsigned char *buf, unsigned char token,
                               unsigned char message_id_msb, unsigned char message_id_lsb, int desc_flags);
                               
bool function_result(const void* result, SparkReturnType::Enum, uint8_t token);

void invokeEventHandlerInternal(uint16_t handlerInfoSize, FilteringEventHandler* handlerInfo,
                const char* event_name, const char* data, void* reserved);

void invokeEventHandlerString(uint16_t handlerInfoSize, FilteringEventHandler* handlerInfo,
                const String& name, const String& data, void* reserved);

void invokeEventHandler(uint16_t handlerInfoSize, FilteringEventHandler* handlerInfo,
                const char* event_name, const char* event_data, void* reserved);

void separate_response(unsigned char *buf,
                                      unsigned char token,
                                      unsigned char code);

void update_ready(unsigned char *buf, unsigned char token);
void update_ready(unsigned char *buf, unsigned char token, uint8_t flags);


bool readBootConfig();

void writeBootConfig();

uint8_t getOTAFlashSlot();

void LED_Toggle();

void set_chunks_received(uint8_t value);

void remove_event_handlers(const char* event_name);

void spark_disconnect();

void notify_update_done(uint8_t* buf);

bool particleConnect();

//this connects to the configured wifi
bool wifiConnect();

bool wifiConnected();

bool wifiWaitForConnection();

bool readDeviceConfig(bool isSystem = false);

unsigned char next_token();

size_t time_request(unsigned char *buf);

bool send_time_request(void);

bool particle_handshake();

void reboot_to_user();

void reboot_to_config();

void reboot_to_fallback_updater();

String spark_deviceID();

void SystemEvents(const char* name, const char* data);

void oak_rom_init();

//this should be called when the Particle library is inited 
void spark_initConfig(bool isSystem = false);

bool spark_internal_connect();

bool spark_connect();

//Spark Serial
void spark_serial_begin();
void spark_serial_end();
int spark_serial_read();
int spark_serial_available();
size_t spark_serial_write(uint8_t b);
void spark_serial_flush();
int spark_serial_peek();
void spark_get_rx(const char* name, const char* data);
void spark_send_tx();
void spark_process(bool internal = false);

String info_response(void);
String set_config_from_JSON(String json);
String configure_ap_from_JSON(String json);
bool provision_keys(bool force);
String pub_key();
void set_system_mode(System_Mode_TypeDef mode);
System_Mode_TypeDef get_system_mode(void);
bool flash_erase_sector(uint32_t sector);
bool is_claimed(void);
uint8_t current_rom(void);
uint8_t config_rom(void);
uint8_t user_rom(void);
uint8_t update_rom(void);
uint8_t ota_reboot(void);
}; // particle_core


#endif // particle_core_h

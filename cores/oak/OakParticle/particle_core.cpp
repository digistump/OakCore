#include "particle_core.h"


//#include <Arduino.h>
#include "../ESP8266WiFi/src/ESP8266WiFi.h"
#include "handshake.h"
#include "messages.h"
#include "coap.h"
#include "aes.h"
#include "rsa.h"
#include "dsakeygen.h"
#include "append_list.h"
#include "appender.h"
#include "file_transfer.h"
#include "crc32.h"

#ifdef __cplusplus
extern "C" {
#endif
  #include <c_types.h>
  #include <user_interface.h>
  #include <mem.h>
  #include <osapi.h>
  #include "espmissingincludes.h"
  #include "oakboot.h"
#ifdef __cplusplus
}
#endif

namespace particle_core {

#define PROTOCOL_BUFFER_SIZE 800
#define QUEUE_SIZE 800

//this has to be aligned 
uint8_t chunk_buffer[512];

WiFiClient pClient; 

static System_Mode_TypeDef system_mode = DEFAULT_MODE;

typedef unsigned short uint16_t;
typedef uint16_t chunk_index_t;

unsigned char queue[PROTOCOL_BUFFER_SIZE];

typedef struct {
  //can cut off here if needed
  char device_id[25];     //device id in hex
  char claim_code[65];   // server public key
  uint8 claimed;   // server public key
  uint8 device_private_key[1216];  // device private key
  uint8 device_public_key[384];   // device public key
  uint8 server_public_key[768]; //also contains the server address at offset 384
  uint8 server_address_type;   //domain or ip of cloud server
  uint8 server_address_length;   //domain or ip of cloud server
  char server_address_domain[254];   //domain or ip of cloud server
  uint8 ota_success;
  uint32 server_address_ip;   //[4]//domain or ip of cloud server
  unsigned short firmware_version;  
  unsigned short system_version;     //
  char version_string[33];    //
  uint8 reserved_flags[32];    //
  uint8 reserved1[32];
  uint8 product_store[24];    
  char ssid[33]; //ssid and terminator
  char passcode[65]; //passcode and terminator
  uint8 channel; //channel number
  int32 third_party_id;    //
  char third_party_data[256];     //
  char first_update_domain[65];
  char first_update_url[65];
  char first_update_fingerprint[60];
  uint8 current_rom_scheme[1];
  uint8 system_update_pending;
  uint8 magic;
  uint8 chksum; 
  //uint8 reserved2[698]; 
} oak_config; 

struct msg {
        uint8_t token;
        size_t len;
        uint8_t* response;
        size_t response_len;
    };


#define SPARK_SERVER_PORT 5683


#define USER_VAR_MAX_COUNT            10
#define USER_VAR_KEY_LENGTH           12

#define USER_FUNC_MAX_COUNT           4
#define USER_FUNC_KEY_LENGTH            12
#define USER_FUNC_ARG_LENGTH            64

#define USER_EVENT_NAME_LENGTH            64
#define USER_EVENT_DATA_LENGTH            64

#define SECTOR_SIZE 0x1000
#define DEVICE_CONFIG_SECTOR 256
#define DEVICE_BACKUP_CONFIG_SECTOR 512
#define DEVICE_CHKSUM_INIT 0xee
#define DEVICE_MAGIC 0xf0
#define DEVICE_CONFIG_SIZE 3398
#define PRIVATE_KEY_LENGTH    (612)
#define PUBLIC_KEY_LENGTH    (162)
/* Length in bytes of DER-encoded 2048-bit RSA public key */
#define SERVER_PUBLIC_KEY_LENGTH   (294)
#define SERVER_DOMAIN_LENGTH   (253)


const CloudVariableTypeBool BOOLEAN;
const CloudVariableTypeInt INT;
const CloudVariableTypeString STRING;
const CloudVariableTypeDouble DOUBLE;

uint8 config_buffer[DEVICE_CONFIG_SIZE];
oak_config *deviceConfig = (oak_config*)config_buffer;
uint8 boot_buffer[BOOT_CONFIG_SIZE];
oakboot_config *bootConfig = (oakboot_config*)boot_buffer;


volatile bool spark_connect_pending = false;

byte device_id[12];

bool spark_initialized = false;


#ifdef DEBUG_SETUP
void ERROR(String out){
  Serial.println(out);
}
#endif
#ifdef DEBUG_SETUP
void INFO(String out){
  Serial.println(out);
}
#endif


aes_context aes;

unsigned char key[16];
unsigned char iv_send[16];
unsigned char iv_receive[16];
unsigned char salt[8];
unsigned short _message_id;
unsigned char _token;
uint32_t last_message_millis;
uint32_t last_chunk_millis;    // NB: also used to synchronize time
unsigned short chunk_index;
unsigned short chunk_size;
bool expecting_ping_ack;
bool initialized;
uint8_t updating;






struct User_Var_Lookup_Table_t
{
    const void *userVar;
    Spark_Data_TypeDef userVarType;
    char userVarKey[USER_VAR_KEY_LENGTH+1];

    const void* (*update)(const char* name, Spark_Data_TypeDef varType, const void* var, void* reserved);
};


struct User_Func_Lookup_Table_t
{
    void* pUserFuncData;
    cloud_function_t pUserFunc;
    char userFuncKey[USER_FUNC_KEY_LENGTH];
};



User_Var_Lookup_Table_t* find_var_by_key_or_add(const char* varKey);
User_Func_Lookup_Table_t* find_func_by_key_or_add(const char* funcKey);



static append_list<User_Var_Lookup_Table_t> vars(5);
static append_list<User_Func_Lookup_Table_t> funcs(5);
FilteringEventHandler event_handlers[5];  


User_Var_Lookup_Table_t* find_var_by_key(const char* varKey)
{
    for (int i = vars.size(); i-->0; )
    {
        if (0 == strncmp(vars[i].userVarKey, varKey, USER_VAR_KEY_LENGTH))
        {
            return &vars[i];
        }
    }
    return NULL;
}


User_Var_Lookup_Table_t* find_var_by_key_or_add(const char* varKey)
{
    User_Var_Lookup_Table_t* result = find_var_by_key(varKey);
    return result ? result : vars.add();
}

User_Func_Lookup_Table_t* find_func_by_key(const char* funcKey)
{
    for (int i = funcs.size(); i-->0; )
    {
        if (0 == strncmp(funcs[i].userFuncKey, funcKey, USER_FUNC_KEY_LENGTH))
        {
            return &funcs[i];
        }
    }
    return NULL;
}

User_Func_Lookup_Table_t* find_func_by_key_or_add(const char* funcKey)
{
    User_Func_Lookup_Table_t* result = find_func_by_key(funcKey);
    return result ? result : funcs.add();
}

int call_raw_user_function(void* data, const char* param, void* reserved)
{
    user_function_int_str_t* fn = (user_function_int_str_t*)(data);
    String p(param);
    return (*fn)(p);
}

int call_std_user_function(void* data, const char* param, void* reserved)
{
    user_std_function_int_str_t* fn = (user_std_function_int_str_t*)(data);
    return (*fn)(String(param));
}

void call_wiring_event_handler(const void* handler_data, const char *event_name, const char *data)
{
    wiring_event_handler_t* fn = (wiring_event_handler_t*)(handler_data);
    (*fn)(event_name, data);
}



bool spark_connected()
{
    return pClient.connected();

}

unsigned short next_message_id()
{
  return ++_message_id;
}


static uint8 calc_device_chksum(uint8 *start, uint8 *end) {
  uint8 chksum = DEVICE_CHKSUM_INIT;
  while(start < end) {
    chksum ^= *start;
    start++;
  }
  return chksum;
}

void writeDeviceConfig(){
    deviceConfig->chksum = calc_device_chksum((uint8*)deviceConfig,(uint8*)&deviceConfig->chksum);
    noInterrupts();
    spi_flash_erase_sector(DEVICE_CONFIG_SECTOR);
    spi_flash_write(DEVICE_CONFIG_SECTOR * SECTOR_SIZE, reinterpret_cast<uint32_t*>(config_buffer), DEVICE_CONFIG_SIZE);
    spi_flash_erase_sector(DEVICE_BACKUP_CONFIG_SECTOR);
    spi_flash_write(DEVICE_BACKUP_CONFIG_SECTOR * SECTOR_SIZE, reinterpret_cast<uint32_t*>(config_buffer), DEVICE_CONFIG_SIZE);
    interrupts();
    
  }

uint8_t hex_nibble(unsigned char c) {
    if (c<'0')
        return 0;
    if (c<='9')
        return c-'0';
    if (c<='Z')
        return c-'A'+10;
    if (c<='z')
        return c-'a'+10;
    return 0;
}

size_t hex_decode(uint8_t* buf, size_t len, const char* hex) {
    unsigned char c = '0'; // any non-null character
    size_t i;
    for (i=0; i<len && c; i++) {
        uint8_t b;
        if (!(c = *hex++))
            break;
        b = hex_nibble(c)<<4;
        if (c) {
            c = *hex++;
            b |= hex_nibble(c);
        }
        *buf++ = b;
    }
    return i;
}

// Returns bytes received or -1 on error
int blocking_send(const unsigned char *buf, int length)
{
  if(!spark_connected())
    return -1;
  #ifdef DEBUG_SETUP
    Serial.println("BLSEND");
  #endif
  pClient.setTimeout(100);
  #ifdef DEBUG_SETUP
  uint32_t start = millis();

  #endif
  int byte_count = pClient.write(buf, length);
  #ifdef DEBUG_SETUP
    Serial.println(byte_count);
    Serial.println((millis()-start)/1000);
  #endif
  if(byte_count==0) 
    byte_count = -1;
  return byte_count;
}

// Returns bytes received or -1 on error
int receive(unsigned char *buf, int length)
{

  pClient.setTimeout(2000);
  int available = pClient.available();
  if(available >= length){
    return pClient.readBytes(buf, length);
  }
  else if(available > 0){
    return pClient.readBytes(buf, available);
  }
  else{
    if(!spark_connected())
      return -1;
    else
      return 0;
  }
}

// Returns bytes received or -1 on error
int blocking_receive(unsigned char *buf, int length)
{
  if(!spark_connected())
    return -1;
  #ifdef DEBUG_SETUP
  Serial.println("BLRECV");

#endif
  pClient.setTimeout(2000);
  int byte_count = pClient.readBytes(buf, length);
  if(byte_count==0) 
    byte_count = -1;
  return byte_count;
}


int set_key(const unsigned char *signed_encrypted_credentials)
{
  unsigned char credentials[40];
  unsigned char hmac[20];

  if (0 != decipher_aes_credentials(deviceConfig->device_private_key,
                                    signed_encrypted_credentials,
                                    credentials))
    return 1;//decrypt error

  calculate_ciphertext_hmac(signed_encrypted_credentials, credentials, hmac);

  if (0 == verify_signature(signed_encrypted_credentials + 128,
                            deviceConfig->server_public_key,
                            hmac))
  {
    memcpy(key,        credentials,      16);
    memcpy(iv_send,    credentials + 16, 16);
    memcpy(iv_receive, credentials + 16, 16);
    memcpy(salt,       credentials + 32,  8);
    _message_id = *(credentials + 32) << 8 | *(credentials + 33);
    _token = *(credentials + 34);

    unsigned int seed;
    memcpy(&seed, credentials + 35, 4);

    randomSeed(seed);

    return 0;
  }
  else return 1;//auth error
}

void encrypt(unsigned char *buf, int length)
{
  aes_setkey_enc(&aes, key, 128);
  aes_crypt_cbc(&aes, AES_ENCRYPT, length, iv_send, buf, buf);
  memcpy(iv_send, buf, 16);
}

void ping(unsigned char *buf)
{
  unsigned short message_id = next_message_id();

  buf[0] = 0x40; // Confirmable, no token
  buf[1] = 0x00; // code signifying empty message
  buf[2] = message_id >> 8;
  buf[3] = message_id & 0xff;

  memset(buf + 4, 12, 12); // PKCS #7 padding

  encrypt(buf, 16);
}

size_t wrap(unsigned char *buf, size_t msglen)
{
  size_t buflen = (msglen & ~15) + 16;
  char pad = buflen - msglen;
  memset(buf + 2 + msglen, pad, pad); // PKCS #7 padding

  encrypt(buf + 2, buflen);

  buf[0] = (buflen >> 8) & 0xff;
  buf[1] = buflen & 0xff;

  return buflen + 2;
}


void hello(unsigned char *buf, bool newly_upgraded)
{
  unsigned short message_id = next_message_id();
  size_t len = Messages::hello(buf+2, message_id, newly_upgraded, PLATFORM_ID, PRODUCT_ID, deviceConfig->firmware_version, false, nullptr, 0);
  wrap(buf, len);
}




inline void coded_ack(unsigned char *buf,
                                     unsigned char code,
                                     unsigned char message_id_msb,
                                     unsigned char message_id_lsb
                                     )
{
  buf[0] = 0x60; // acknowledgment, no token
  buf[1] = code;
  buf[2] = message_id_msb;
  buf[3] = message_id_lsb;

  memset(buf + 4, 12, 12); // PKCS #7 padding

  encrypt(buf, 16);
}

inline void coded_ack(unsigned char *buf,
                                     unsigned char token,
                                     unsigned char code,
                                     unsigned char message_id_msb,
                                     unsigned char message_id_lsb)
{
  buf[0] = 0x61; // acknowledgment, one-byte token
  buf[1] = code;
  buf[2] = message_id_msb;
  buf[3] = message_id_lsb;
  buf[4] = token;

  memset(buf + 5, 11, 11); // PKCS #7 padding

  encrypt(buf, 16);
}


void variable_value(unsigned char *buf,
                                   unsigned char token,
                                   unsigned char message_id_msb,
                                   unsigned char message_id_lsb,
                                   bool return_value)
{
  buf[0] = 0x61; // acknowledgment, one-byte token
  buf[1] = 0x45; // response code 2.05 CONTENT
  buf[2] = message_id_msb;
  buf[3] = message_id_lsb;
  buf[4] = token;
  buf[5] = 0xff; // payload marker
  buf[6] = return_value ? 1 : 0;

  memset(buf + 7, 9, 9); // PKCS #7 padding

  encrypt(buf, 16);
}

void variable_value(unsigned char *buf,
                                   unsigned char token,
                                   unsigned char message_id_msb,
                                   unsigned char message_id_lsb,
                                   int return_value)
{
  buf[0] = 0x61; // acknowledgment, one-byte token
  buf[1] = 0x45; // response code 2.05 CONTENT
  buf[2] = message_id_msb;
  buf[3] = message_id_lsb;
  buf[4] = token;
  buf[5] = 0xff; // payload marker
  buf[6] = return_value >> 24;
  buf[7] = return_value >> 16 & 0xff;
  buf[8] = return_value >> 8 & 0xff;
  buf[9] = return_value & 0xff;

  memset(buf + 10, 6, 6); // PKCS #7 padding

  encrypt(buf, 16);
}

void variable_value(unsigned char *buf,
                                   unsigned char token,
                                   unsigned char message_id_msb,
                                   unsigned char message_id_lsb,
                                   double return_value)
{
  buf[0] = 0x61; // acknowledgment, one-byte token
  buf[1] = 0x45; // response code 2.05 CONTENT
  buf[2] = message_id_msb;
  buf[3] = message_id_lsb;
  buf[4] = token;
  buf[5] = 0xff; // payload marker

  memcpy(buf + 6, &return_value, 8);

  memset(buf + 14, 2, 2); // PKCS #7 padding

  encrypt(buf, 16);
}

// Returns the length of the buffer to send
int variable_value(unsigned char *buf,
                                  unsigned char token,
                                  unsigned char message_id_msb,
                                  unsigned char message_id_lsb,
                                  const void *return_value,
                                  int length)
{
  buf[0] = 0x61; // acknowledgment, one-byte token
  buf[1] = 0x45; // response code 2.05 CONTENT
  buf[2] = message_id_msb;
  buf[3] = message_id_lsb;
  buf[4] = token;
  buf[5] = 0xff; // payload marker

  memcpy(buf + 6, return_value, length);

  int msglen = 6 + length;
  int buflen = (msglen & ~15) + 16;
  char pad = buflen - msglen;
  memset(buf + msglen, pad, pad); // PKCS #7 padding

  encrypt(buf, buflen);

  return buflen;
}

uint32_t timestamp_offset;
uint32_t last_time_offset;

void set_time(uint32_t time){
  timestamp_offset = time - (millis()/1000);
  last_time_offset = millis()/1000;
}

uint32_t get_time(){
  //as long as we get time once every 98 days this should be OK
  if(millis()/1000<last_time_offset){
    timestamp_offset += 4294968;
  }
  last_time_offset = millis()/1000;
  return timestamp_offset+last_time_offset;
}

void handle_time_response(uint32_t time)
{
    // deduct latency
    uint32_t latency = last_chunk_millis ? (millis()-last_chunk_millis)/2000 : 0;
    last_chunk_millis = 0;
    set_time(time-latency);
}

int numUserFunctions(void)
{
    return funcs.size();
}

const char* getUserFunctionKey(int function_index)
{
    return funcs[function_index].userFuncKey;
}

int numUserVariables(void)
{
    return vars.size();
}

const char* getUserVariableKey(int variable_index)
{
    return vars[variable_index].userVarKey;
}

int userVarType(const char *varKey)
{
    User_Var_Lookup_Table_t* item = find_var_by_key(varKey);
    return item ? item->userVarType : -1;
}

SparkReturnType::Enum wrapVarTypeInEnum(const char *varKey)
{
    switch (userVarType(varKey))
    {
        case 1:
            return SparkReturnType::BOOLEAN;
        case 4:
            return SparkReturnType::STRING;
        case 9:
            return SparkReturnType::DOUBLE;
        case 2:
        default:
            return SparkReturnType::INT;
    }
}

bool send_subscription(const char *event_name, const char *device_id)
{
  uint16_t msg_id = next_message_id();
  size_t msglen = subscription(queue + 2, msg_id, event_name, device_id);

  size_t buflen = (msglen & ~15) + 16;
  char pad = buflen - msglen;
  memset(queue + 2 + msglen, pad, pad); // PKCS #7 padding

  encrypt(queue + 2, buflen);

  queue[0] = (buflen >> 8) & 0xff;
  queue[1] = buflen & 0xff;

  return (0 <= blocking_send(queue, buflen + 2));
}

bool send_subscription(const char *event_name,
                                      SubscriptionScope::Enum scope)
{
  uint16_t msg_id = next_message_id();
  size_t msglen = subscription(queue + 2, msg_id, event_name, scope);

  size_t buflen = (msglen & ~15) + 16;
  char pad = buflen - msglen;
  memset(queue + 2 + msglen, pad, pad); // PKCS #7 padding

  encrypt(queue + 2, buflen);

  queue[0] = (buflen >> 8) & 0xff;
  queue[1] = buflen & 0xff;

  return (0 <= blocking_send(queue, buflen + 2));
}

void send_subscriptions()
{
  const int NUM_HANDLERS = sizeof(event_handlers) / sizeof(FilteringEventHandler);
  for (int i = 0; i < NUM_HANDLERS; i++)
  {
    if (NULL != event_handlers[i].handler)
    {
        if (event_handlers[i].device_id[0])
        {
            send_subscription(event_handlers[i].filter, event_handlers[i].device_id);
        }
        else
        {
            send_subscription(event_handlers[i].filter, event_handlers[i].scope);
        }
    }
  }
}

bool event_handler_exists(const char *event_name, EventHandler handler,
    void *handler_data, SubscriptionScope::Enum scope, const char* id)
{
  const int NUM_HANDLERS = sizeof(event_handlers) / sizeof(FilteringEventHandler);
  for (int i = 0; i < NUM_HANDLERS; i++)
  {
      if (event_handlers[i].handler==handler &&
          event_handlers[i].handler_data==handler_data &&
          event_handlers[i].scope==scope) {
        const size_t MAX_FILTER_LEN = sizeof(event_handlers[i].filter);
        const size_t FILTER_LEN = strnlen(event_name, MAX_FILTER_LEN);
        if (!strncmp(event_handlers[i].filter, event_name, FILTER_LEN)) {
            const size_t MAX_ID_LEN = sizeof(event_handlers[i].device_id)-1;
            const size_t id_len = id ? strnlen(id, MAX_ID_LEN) : 0;
            if (id_len)
                return !strncmp(event_handlers[i].device_id, id, id_len);
            else
                return !event_handlers[i].device_id[0];
        }
      }
  }
  return false;
}

bool add_event_handler(const char *event_name, EventHandler handler,
    void *handler_data, SubscriptionScope::Enum scope, const char* id)
{
    if (event_handler_exists(event_name, handler, handler_data, scope, id))
        return true;

  const int NUM_HANDLERS = sizeof(event_handlers) / sizeof(FilteringEventHandler);
  for (int i = 0; i < NUM_HANDLERS; i++)
  {
    if (NULL == event_handlers[i].handler)
    {
      const size_t MAX_FILTER_LEN = sizeof(event_handlers[i].filter);
      const size_t FILTER_LEN = strnlen(event_name, MAX_FILTER_LEN);
      memcpy(event_handlers[i].filter, event_name, FILTER_LEN);
      memset(event_handlers[i].filter + FILTER_LEN, 0, MAX_FILTER_LEN - FILTER_LEN);
      event_handlers[i].handler = handler;
      event_handlers[i].handler_data = handler_data;
      event_handlers[i].device_id[0] = 0;
        const size_t MAX_ID_LEN = sizeof(event_handlers[i].device_id)-1;
        const size_t id_len = id ? strnlen(id, MAX_ID_LEN) : 0;
        memcpy(event_handlers[i].device_id, id, id_len);
        event_handlers[i].device_id[id_len] = 0;
        event_handlers[i].scope = scope;
      return true;
    }
  }
  return false;
}


const void *getUserVar(const char *varKey)
{
    User_Var_Lookup_Table_t* item = find_var_by_key(varKey);
    const void* result = nullptr;
    if (item) {
      if (item->update)
            result = item->update(item->userVarKey, item->userVarType, item->userVar, nullptr);
      else
            result = item->userVar;
    }
    return result;
}

void userFuncScheduleImpl(User_Func_Lookup_Table_t* item, const char* paramString, bool freeParamString, FunctionResultCallback callback)
{
    int result = item->pUserFunc(item->pUserFuncData, paramString, NULL);
    if (freeParamString)
        delete paramString;

    callback((const void*)long(result), SparkReturnType::INT);
}

int userFuncSchedule(const char *funcKey, const char *paramString, FunctionResultCallback callback, void* reserved)
{
    // for now, we invoke the function directly and return the result via the callback
    User_Func_Lookup_Table_t* item = find_func_by_key(funcKey);
    if (!item)
        return -1;

    userFuncScheduleImpl(item, paramString, false, callback);

    return 0;
}


SubscriptionScope::Enum convert(Spark_Subscription_Scope_TypeDef subscription_type)
{
    return(subscription_type==MY_DEVICES) ? SubscriptionScope::MY_DEVICES : SubscriptionScope::FIREHOSE;
}

bool register_event(const char* eventName, SubscriptionScope::Enum event_scope, const char* deviceID)
{
    bool success;
    if (deviceID)
        success = send_subscription(eventName, deviceID);
    else
        success = send_subscription(eventName, event_scope);
    return success;
}

bool spark_subscribe(const char *eventName, EventHandler handler, void* handler_data,
        Spark_Subscription_Scope_TypeDef scope, const char* deviceID, void* reserved)
{
    //SYSTEM_THREAD_CONTEXT_SYNC(spark_subscribe(eventName, handler, handler_data, scope, deviceID, reserved));
    auto event_scope = convert(scope);
    bool success = add_event_handler(eventName, handler, handler_data, event_scope, deviceID);
    if (success && spark_connected())
    {
        register_event(eventName, event_scope, deviceID);
    }
    return success;
}


inline EventType::Enum convert(Spark_Event_TypeDef eventType) {
    return eventType==PUBLIC ? EventType::PUBLIC : EventType::PRIVATE;
}

inline bool is_system(const char* event_name) {
    // if there were a strncmpi this would be easier!
    char prefix[6];
    if (!*event_name || strlen(event_name)<5)
        return false;
    memcpy(prefix, event_name, 5);
    prefix[5] = '\0';
    return !strcasecmp(prefix, "spark");
}

// Returns true on success, false on sending timeout or rate-limiting failure
bool send_event(const char *event_name, const char *data,
                               int ttl, EventType::Enum event_type)
{
  if (updating)
  {
    return false;
  }

  bool is_system_event = is_system(event_name);

  if (is_system_event) {
      static uint16_t lastMinute = 0;
      static uint8_t eventsThisMinute = 0;

      uint16_t currentMinute = uint16_t(millis()>>16);
      if (currentMinute==lastMinute) {      // == handles millis() overflow
          if (eventsThisMinute==255)
              return false;
      }
      else {
          lastMinute = currentMinute;
          eventsThisMinute = 0;
      }
      eventsThisMinute++;
  }
  else {
    static uint32_t recent_event_ticks[5] = {
      (uint32_t) -1000, (uint32_t) -1000,
      (uint32_t) -1000, (uint32_t) -1000,
      (uint32_t) -1000 };
    static int evt_tick_idx = 0;

    uint32_t now = recent_event_ticks[evt_tick_idx] = millis();
    evt_tick_idx++;
    evt_tick_idx %= 5;
    if (now - recent_event_ticks[evt_tick_idx] < 1000)
    {
      // exceeded allowable burst of 4 events per second
      return false;
    }
  }
  uint16_t msg_id = next_message_id();
  size_t msglen = Messages::event(queue + 2, msg_id, event_name, data, ttl, event_type, false);
  size_t wrapped_len = wrap(queue, msglen);

  return (0 <= blocking_send(queue, wrapped_len));
}

bool spark_send_event(const char* name, const char* data, int ttl, Spark_Event_TypeDef eventType, void* reserved)
{
    //SYSTEM_THREAD_CONTEXT_SYNC(spark_send_event(name, data, ttl, eventType, reserved));

    //return spark_protocol_send_event(sp, name, data, ttl, convert(eventType), NULL);
    return send_event(name, data, ttl, convert(eventType));
}


bool spark_variable(const char *varKey, const void *userVar, Spark_Data_TypeDef userVarType, spark_variable_t* extra)
{
    //SYSTEM_THREAD_CONTEXT_SYNC(spark_variable(varKey, userVar, userVarType, extra));

    User_Var_Lookup_Table_t* item = NULL;
    if (NULL != userVar && NULL != varKey && strlen(varKey)<=USER_VAR_KEY_LENGTH)
    {
        if ((item=find_var_by_key_or_add(varKey))!=NULL)
        {
            item->userVar = userVar;
            item->userVarType = userVarType;
            if (extra) {
                item->update = extra->update;
            }
            memset(item->userVarKey, 0, USER_VAR_KEY_LENGTH);
            memcpy(item->userVarKey, varKey, USER_VAR_KEY_LENGTH);
        }
    }
    return item!=NULL;
}

void function_return(unsigned char *buf,
                                    unsigned char token,
                                    int return_value)
{
  unsigned short message_id = next_message_id();

  buf[0] = 0x51; // non-confirmable, one-byte token
  buf[1] = 0x44; // response code 2.04 CHANGED
  buf[2] = message_id >> 8;
  buf[3] = message_id & 0xff;
  buf[4] = token;
  buf[5] = 0xff; // payload marker
  buf[6] = return_value >> 24;
  buf[7] = return_value >> 16 & 0xff;
  buf[8] = return_value >> 8 & 0xff;
  buf[9] = return_value & 0xff;

  memset(buf + 10, 6, 6); // PKCS #7 padding

  encrypt(buf, 16);
}



bool spark_function_internal(const cloud_function_descriptor* desc, void* reserved)
{
    User_Func_Lookup_Table_t* item = NULL;
    if (NULL != desc->fn && NULL != desc->funcKey && strlen(desc->funcKey)<=USER_FUNC_KEY_LENGTH)
    {
        if ((item=find_func_by_key(desc->funcKey)) || (item = funcs.add()))
        {
            item->pUserFunc = desc->fn;
            item->pUserFuncData = desc->data;
            memset(item->userFuncKey, 0, USER_FUNC_KEY_LENGTH);
            memcpy(item->userFuncKey, desc->funcKey, USER_FUNC_KEY_LENGTH);
        }
    }
    return item!=NULL;
}

/**
 * This is the original released signature for firmware version 0 and needs to remain like this.
 * (The original returned void - we can safely change to bool.)
 */
bool spark_function(const char *funcKey, p_user_function_int_str_t pFunc, void* reserved)
{
    //SYSTEM_THREAD_CONTEXT_SYNC(spark_function(funcKey, pFunc, reserved));

    bool result;
    if (funcKey) {                          // old call, with funcKey != NULL
        cloud_function_descriptor desc;
        desc.funcKey = funcKey;
        desc.fn = call_raw_user_function;
        desc.data = (void*)pFunc;
        result = spark_function_internal(&desc, NULL);
    }
    else {      // new call - pFunc is actually a pointer to a descriptor
        result = spark_function_internal((cloud_function_descriptor*)pFunc, reserved);
    }
    return result;
}

bool register_function(cloud_function_t fn, void* data, const char* funcKey)
{
    cloud_function_descriptor desc;
    memset(&desc, 0, sizeof(desc));
    desc.size = sizeof(desc);
    desc.fn = fn;
    desc.data = (void*)data;
    desc.funcKey = funcKey;
    return spark_function(NULL, (user_function_int_str_t*)&desc, NULL);
}

String buffer_to_string(const uint8_t *buf,size_t length){
  String result = "";
  for(uint8_t i = 0; i<length; i++){
    result += buf[i];
  }
  return result;
}
bool spark_describe_called = false;
int description(unsigned char *buf, unsigned char token,
                               unsigned char message_id_msb, unsigned char message_id_lsb, int desc_flags)
{
    spark_describe_called = true;
    buf[0] = 0x61; // acknowledgment, one-byte token
    buf[1] = 0x45; // response code 2.05 CONTENT
    buf[2] = message_id_msb;
    buf[3] = message_id_lsb;
    buf[4] = token;
    buf[5] = 0xff; // payload marker

    BufferAppender appender(buf+6, QUEUE_SIZE-8);
    appender.append("{");
    bool has_content = false;

    if (desc_flags && DESCRIBE_APPLICATION) {
        has_content = true;
      appender.append("\"f\":[");

      int num_keys = numUserFunctions();
      int i;
      for (i = 0; i < num_keys; ++i)
      {
        if (i)
        {
            appender.append(',');
        }
        appender.append('"');

        const char* key = getUserFunctionKey(i);
        size_t function_name_length = strlen(key);
        if (MAX_FUNCTION_KEY_LENGTH < function_name_length)
        {
          function_name_length = MAX_FUNCTION_KEY_LENGTH;
        }
        appender.append((const uint8_t*)key, function_name_length);
        appender.append('"');
      }

      appender.append("],\"v\":{");

      num_keys = numUserVariables();
      for (i = 0; i < num_keys; ++i)
      {
        if (i)
        {
            appender.append(',');
        }
        appender.append('"');
        const char* key = getUserVariableKey(i);
        size_t variable_name_length = strlen(key);
        SparkReturnType::Enum t = wrapVarTypeInEnum(key);
        if (MAX_VARIABLE_KEY_LENGTH < variable_name_length)
        {
          variable_name_length = MAX_VARIABLE_KEY_LENGTH;
        }
        appender.append((const uint8_t*)key, variable_name_length);
        appender.append("\":");
        appender.append('0' + (char)t);
      }
      appender.append('}');
    }

    if ((desc_flags&DESCRIBE_SYSTEM)) {
    //if (descriptor.append_system_info && (desc_flags&DESCRIBE_SYSTEM)) {
      if (has_content)
        appender.append(',');
      //descriptor.append_system_info(append_instance, &appender, NULL);
      char number_buffer[4];
      appender.append("\"p\":82,\"m\":[{\"s\":1040368,\"l\":\"m\",\"vc\":30,\"vv\":30,\"f\":\"s\",\"n\":\"1\",\"v\":");
      sprintf(number_buffer,"%d",deviceConfig->system_version);
      appender.append(number_buffer);
      appender.append(",\"d\":[]},{\"s\":1040368,\"l\":\"m\",\"vc\":30,\"vv\":30,\"u\":\"0\",\"f\":\"u\",\"n\":\"1\",\"v\":1,\"d\":[{\"f\":\"s\",\"n\":\"1\",\"v\":");
      sprintf(number_buffer,"%d",OAK_SYSTEM_VERSION_INTEGER);
      appender.append(number_buffer);
      appender.append(",\"_\":\"\"}]}]");
    }
    appender.append('}');

    int msglen = appender.next() - (uint8_t *)buf;


    int buflen = (msglen & ~15) + 16;
    char pad = buflen - msglen;
    memset(buf+msglen, pad, pad); // PKCS #7 padding

    encrypt(buf, buflen);
    return buflen;
}
/*
int description(unsigned char *buf, unsigned char token,
                               unsigned char message_id_msb, unsigned char message_id_lsb, int desc_flags)
{
    buf[0] = 0x61; // acknowledgment, one-byte token
    buf[1] = 0x45; // response code 2.05 CONTENT
    buf[2] = message_id_msb;
    buf[3] = message_id_lsb;
    buf[4] = token;
    buf[5] = 0xff; // payload marker

    String content = "";

    //BufferAppender appender(buf+6, QUEUE_SIZE-8);
    content += "{";
    bool has_content = false;

    if (desc_flags && DESCRIBE_APPLICATION) {
        has_content = true;
      content += "\"f\":[";

      int num_keys = numUserFunctions();
      int i;
      for (i = 0; i < num_keys; ++i)
      {
        if (i)
        {
            content += ",";
        }
        content += "\"";

        const char* key = getUserFunctionKey(i);
        size_t function_name_length = strlen(key);
        if (MAX_FUNCTION_KEY_LENGTH < function_name_length)
        {
          function_name_length = MAX_FUNCTION_KEY_LENGTH;
        }
        content += buffer_to_string((const uint8_t*)key, function_name_length);
        content += "\"";
      }

      content += "],\"v\":{";

      num_keys = numUserVariables();
      for (i = 0; i < num_keys; ++i)
      {
        if (i)
        {
            content += ",";
        }
        content += "\"";
        const char* key = getUserVariableKey(i);
        size_t variable_name_length = strlen(key);
        SparkReturnType::Enum t = wrapVarTypeInEnum(key);
        if (MAX_VARIABLE_KEY_LENGTH < variable_name_length)
        {
          variable_name_length = MAX_VARIABLE_KEY_LENGTH;
        }
        content += buffer_to_string((const uint8_t*)key, variable_name_length);
        content += "\":";
        content += String('0' + (char)t);
      }
      content += "}";
    }

    if (desc_flags&DESCRIBE_SYSTEM) {
      if (has_content)
        content += ",";
      //descriptor.append_system_info(append_instance, &appender, NULL);
      content += "\"p\":82,\"m\":[]";
    }
    content += "}";

    
    //truncate if too long
     if(content.length() > QUEUE_SIZE-8){
      content = content.substring(0,QUEUE_SIZE-8);
    }

    int msglen = ((uint8_t *)buf+6 + content.length()) - (uint8_t *)buf;


    int buflen = (msglen & ~15) + 16;
    char pad = buflen - msglen;
    memset(buf+msglen, pad, pad); // PKCS #7 padding

    encrypt(buf, buflen);
    return buflen;
}

*/
bool function_result(const void* result, SparkReturnType::Enum, uint8_t token)
{
    // send return value
    queue[0] = 0;
    queue[1] = 16;
    function_return(queue + 2, token, long(result));
    if (0 > blocking_send(queue, 18))
    {
      // error
      return false;
    }
    return true;
}

char function_arg[MAX_FUNCTION_ARG_LENGTH];

bool handle_function_call(msg& message)
{
    // copy the function key
    char function_key[13];
    memset(function_key, 0, 13);
    int function_key_length = queue[7] & 0x0F;
    memcpy(function_key, queue + 8, function_key_length);

    // How long is the argument?
    size_t q_index = 8 + function_key_length;
    size_t query_length = queue[q_index] & 0x0F;
    if (13 == query_length)
    {
      ++q_index;
      query_length = 13 + queue[q_index];
    }
    else if (14 == query_length)
    {
      ++q_index;
      query_length = queue[q_index] << 8;
      ++q_index;
      query_length |= queue[q_index];
      query_length += 269;
    }

    bool has_function = false;

    // allocated memory bounds check
    if (MAX_FUNCTION_ARG_LENGTH > query_length)
    {
        // save a copy of the argument
        memcpy(function_arg, queue + q_index + 1, query_length);
        function_arg[query_length] = 0; // null terminate string
        has_function = true;
    }

    uint8_t* msg_to_send = message.response;
    // send ACK
    msg_to_send[0] = 0;
    msg_to_send[1] = 16;
    coded_ack(msg_to_send + 2, has_function ? 0x00 : RESPONSE_CODE(4,00), queue[2], queue[3]);
    if (0 > blocking_send(msg_to_send, 18))
    {
      // error
      return false;
    }

    // call the given user function
    auto callback = [=] (const void* result, SparkReturnType::Enum resultType ) { return function_result(result, resultType, message.token); };
    userFuncSchedule(function_key, function_arg, callback, NULL);
    return true;
}


void invokeEventHandlerInternal(uint16_t handlerInfoSize, FilteringEventHandler* handlerInfo,
                const char* event_name, const char* data, void* reserved)
{
    if(handlerInfo->handler_data)
    {
        EventHandlerWithData handler = (EventHandlerWithData) handlerInfo->handler;
        handler(handlerInfo->handler_data, event_name, data);
    }
    else
    {
        handlerInfo->handler(event_name, data);
    }
}

void invokeEventHandlerString(uint16_t handlerInfoSize, FilteringEventHandler* handlerInfo,
                const String& name, const String& data, void* reserved)
{
    invokeEventHandlerInternal(handlerInfoSize, handlerInfo, name.c_str(), data.c_str(), reserved);
}


void invokeEventHandler(uint16_t handlerInfoSize, FilteringEventHandler* handlerInfo,
                const char* event_name, const char* event_data, void* reserved)
{
    invokeEventHandlerInternal(handlerInfoSize, handlerInfo, event_name, event_data, reserved);
    
}

volatile uint32_t lastCloudEvent = 0;

void handle_event(msg& message)
{
    const unsigned len = message.len;

    // fist decode the event data before looking for a handler
    unsigned char pad = queue[len - 1];
    if (0 == pad || 16 < pad)
    {
        // ignore bad message, PKCS #7 padding must be 1-16
        return;
    }
    // end of CoAP message
    unsigned char *end = queue + len - pad;

    unsigned char *event_name = queue + 6;
    size_t event_name_length = CoAP::option_decode(&event_name);
    if (0 == event_name_length)
    {
        // error, malformed CoAP option
        return;
    }

    unsigned char *next_src = event_name + event_name_length;
    unsigned char *next_dst = next_src;
    while (next_src < end && 0x00 == (*next_src & 0xf0))
    {
      // there's another Uri-Path option, i.e., event name with slashes
      size_t option_len = CoAP::option_decode(&next_src);
      *next_dst++ = '/';
      if (next_dst != next_src)
      {
        // at least one extra byte has been used to encode a CoAP Uri-Path option length
        memmove(next_dst, next_src, option_len);
      }
      next_src += option_len;
      next_dst += option_len;
    }
    event_name_length = next_dst - event_name;

    if (next_src < end && 0x30 == (*next_src & 0xf0))
    {
      // Max-Age option is next, which we ignore
      size_t next_len = CoAP::option_decode(&next_src);
      next_src += next_len;
    }

    unsigned char *data = NULL;
    if (next_src < end && 0xff == *next_src)
    {
      // payload is next
      data = next_src + 1;
      // null terminate data string
      *end = 0;
    }
    // null terminate event name string
    event_name[event_name_length] = 0;

  const int NUM_HANDLERS = sizeof(event_handlers) / sizeof(FilteringEventHandler);
  for (int i = 0; i < NUM_HANDLERS; i++)
  {
    if (NULL == event_handlers[i].handler)
    {
       break;
    }
    const size_t MAX_FILTER_LENGTH = sizeof(event_handlers[i].filter);
    const size_t filter_length = strnlen(event_handlers[i].filter, MAX_FILTER_LENGTH);

    if (event_name_length < filter_length)
    {
      // does not match this filter, try the next event handler
      continue;
    }

    const int cmp = memcmp(event_handlers[i].filter, event_name, filter_length);
    if (0 == cmp)
    {
        // don't call the handler directly, use a callback for it.
        if (!invokeEventHandler)
        {
            if(event_handlers[i].handler_data)
            {
                EventHandlerWithData handler = (EventHandlerWithData) event_handlers[i].handler;
                handler(event_handlers[i].handler_data, (char *)event_name, (char *)data);
            }
            else
            {
                event_handlers[i].handler((char *)event_name, (char *)data);
            }
        }
        else
        {
            invokeEventHandler(sizeof(FilteringEventHandler), &event_handlers[i], (const char*)event_name, (const char*)data, NULL);
        }
    }
    // else continue the for loop to try the next handler
  }
}

bool send_description(int description_flags, msg& message)
{
    int desc_len = description(queue + 2, message.token, queue[2], queue[3], description_flags);
    queue[0] = (desc_len >> 8) & 0xff;
    queue[1] = desc_len & 0xff;
    return blocking_send(queue, desc_len + 2)>=0;
}


void empty_ack(unsigned char *buf,
                          unsigned char message_id_msb,
                          unsigned char message_id_lsb) {
        coded_ack(buf, 0, message_id_msb, message_id_lsb);
    };






FileTransfer::Descriptor file;
unsigned chunk_bitmap_size()
{
    return (file.chunk_count(chunk_size)+7)/8;
}

uint8_t* chunk_bitmap()
{
    return &queue[QUEUE_SIZE-chunk_bitmap_size()];
}

chunk_index_t missed_chunk_index;

void separate_response_with_payload(unsigned char *buf,
                                      unsigned char token,
                                      unsigned char code,
                                      unsigned char* payload,
                                      unsigned payload_len)
{
  unsigned short message_id = next_message_id();

  buf[0] = 0x51; // non-confirmable, one-byte token
  buf[1] = code;
  buf[2] = message_id >> 8;
  buf[3] = message_id & 0xff;
  buf[4] = token;

  unsigned len = 5;
  // for now, assume the payload is less than 9
  if (payload && payload_len) {
      buf[5] = 0xFF;
      memcpy(buf+6, payload, payload_len);
      len += 1 + payload_len;
  }

  memset(buf + len, 16-len, 16-len); // PKCS #7 padding

  encrypt(buf, 16);
}


inline bool is_chunk_received(chunk_index_t idx)
{
    return (chunk_bitmap()[idx>>3] & uint8_t(1<<(idx&7)));
}


void separate_response(unsigned char *buf,
                                      unsigned char token,
                                      unsigned char code)
{
    separate_response_with_payload(buf, token, code, NULL, 0);
}

chunk_index_t next_chunk_missing(chunk_index_t start)
{
    chunk_index_t chunk = NO_CHUNKS_MISSING;
    chunk_index_t chunks = file.chunk_count(chunk_size);
    chunk_index_t idx = start;
    for (;idx<chunks; idx++)
    {
        if (!is_chunk_received(idx))
        {
            //serial_dump("next missing chunk %d from %d", idx, start);
            chunk = idx;
            break;
        }
    }
    return chunk;
}

void chunk_received(unsigned char *buf,
                                   unsigned char token,
                                   ChunkReceivedCode::Enum code)
{
  separate_response(buf, token, code);
}


int send_missing_chunks(int count)
{
    int sent = 0;
    chunk_index_t idx = 0;

    uint8_t* buf = queue+2;
    unsigned short message_id = next_message_id();
    buf[0] = 0x40; // confirmable, no token
    buf[1] = 0x01; // code 0.01 GET
    buf[2] = message_id >> 8;
    buf[3] = message_id & 0xff;
    buf[4] = 0xb1; // one-byte Uri-Path option
    buf[5] = 'c';
    buf[6] = 0xff; // payload marker

    while ((idx=next_chunk_missing(chunk_index_t(idx)))!=NO_CHUNKS_MISSING && sent<count)
    {
        buf[(sent*2)+7] = idx >> 8;
        buf[(sent*2)+8] = idx & 0xFF;

        missed_chunk_index = idx;
        idx++;
        sent++;
    }

    if (sent>0) {
        //serial_dump("Sent %d missing chunks", sent);

        size_t message_size = 7+(sent*2);
        message_size = wrap(queue, message_size);
        if (0 > blocking_send(queue, message_size))
            return -1;
    }
    return sent;
}

void chunk_missed(unsigned char *buf, unsigned short chunk_index)
{
  unsigned short message_id = next_message_id();

  buf[0] = 0x40; // confirmable, no token
  buf[1] = 0x01; // code 0.01 GET
  buf[2] = message_id >> 8;
  buf[3] = message_id & 0xff;
  buf[4] = 0xb1; // one-byte Uri-Path option
  buf[5] = 'c';
  buf[6] = 0xff; // payload marker
  buf[7] = chunk_index >> 8;
  buf[8] = chunk_index & 0xff;

  memset(buf + 9, 7, 7); // PKCS #7 padding

  encrypt(buf, 16);
}

void update_ready(unsigned char *buf, unsigned char token)
{
    separate_response_with_payload(buf, token, 0x44, NULL, 0);
}

void update_ready(unsigned char *buf, unsigned char token, uint8_t flags)
{
    separate_response_with_payload(buf, token, 0x44, &flags, 1);
}



static uint8 calc_boot_chksum(uint8 *start, uint8 *end) {
    uint8 chksum = CHKSUM_INIT;
    while(start < end) {
        chksum ^= *start;
        start++;
    }
    return chksum;
}


bool readBootConfig(){
    noInterrupts();
    spi_flash_read(BOOT_CONFIG_SECTOR * SECTOR_SIZE, reinterpret_cast<uint32_t*>(boot_buffer), BOOT_CONFIG_SIZE);
    
    if(bootConfig->magic != BOOT_CONFIG_MAGIC || bootConfig->chksum != calc_boot_chksum((uint8*)bootConfig, (uint8*)&bootConfig->chksum)){
        
        //load the backup and copy to main
        spi_flash_read(BOOT_BACKUP_CONFIG_SECTOR * SECTOR_SIZE, reinterpret_cast<uint32_t*>(boot_buffer), BOOT_CONFIG_SIZE);
        spi_flash_erase_sector(BOOT_CONFIG_SECTOR);
        spi_flash_write(BOOT_CONFIG_SECTOR * SECTOR_SIZE, reinterpret_cast<uint32_t*>(boot_buffer), BOOT_CONFIG_SIZE);
        
    }
    interrupts();
    
    if(bootConfig->magic != BOOT_CONFIG_MAGIC || bootConfig->chksum != calc_boot_chksum((uint8*)bootConfig, (uint8*)&bootConfig->chksum)){
        return false;
    }
    
    return true;
}

void writeBootConfig(){
    noInterrupts();
    bootConfig->chksum = calc_boot_chksum((uint8*)bootConfig,(uint8*)&bootConfig->chksum);
    spi_flash_erase_sector(BOOT_CONFIG_SECTOR);
    spi_flash_write(BOOT_CONFIG_SECTOR * SECTOR_SIZE, reinterpret_cast<uint32_t*>(boot_buffer), BOOT_CONFIG_SIZE);
    spi_flash_erase_sector(BOOT_BACKUP_CONFIG_SECTOR);
    spi_flash_write(BOOT_BACKUP_CONFIG_SECTOR * SECTOR_SIZE, reinterpret_cast<uint32_t*>(boot_buffer), BOOT_CONFIG_SIZE);
    interrupts();
    
}




#define FLASH_MAX_SIZE          (unsigned long)(0x100000 - 0x2000)
#define OTA_CHUNK_SIZE          (unsigned long)512

uint8_t getOTAFlashSlot(){
    if(bootConfig->program_rom != 0 && bootConfig->config_rom != 0)
      return 0;
    else if(bootConfig->program_rom != 4 && bootConfig->config_rom != 4)
      return 4;
    else
      return 8;
}

bool status_led_state = false;
#define STATUS_LED 1
void LED_Toggle(){
  status_led_state = !status_led_state;
  digitalWrite(STATUS_LED, status_led_state);
}

int prepare_for_firmware_update(FileTransfer::Descriptor& file, uint32_t flags, void* reserved)
{
    #ifdef DEBUG_SETUP
  Serial.println("FIRMWARE");

#endif
    file.file_address = bootConfig->roms[getOTAFlashSlot()];// + file.chunk_address;

    // chunk_size 0 indicates defaults.
    if (file.chunk_size==0) {
        file.chunk_size = OTA_CHUNK_SIZE;
        file.file_length = FLASH_MAX_SIZE;
    }

    int result = 0;
    if (flags & 1) {
        // only check address
    }
    else {
        pinMode(STATUS_LED, OUTPUT);
        if (file.store!=FileTransfer::Store::FIRMWARE)
          return 1;
    }
    return result;
}

void set_chunks_received(uint8_t value)
{
    size_t bytes = chunk_bitmap_size();
    if (bytes)
      memset(queue+QUEUE_SIZE-bytes, value, bytes);
}

uint16_t last_chunk = 0;


bool handle_update_begin(msg& message)
{
    // send ACK
    uint8_t* msg_to_send = message.response;
    *msg_to_send = 0;
    *(msg_to_send + 1) = 16;

    uint8_t flags = 0;
    int actual_len = message.len - queue[message.len-1];
    if (actual_len>=20 && queue[7]==0xFF) {
        flags = decode_uint8(queue+8);
        file.chunk_size = decode_uint16(queue+9);
        file.file_length = decode_uint32(queue+11);
        file.store = FileTransfer::Store::Enum(decode_uint8(queue+15));
        file.file_address = decode_uint32(queue+16);
        file.chunk_address = file.file_address;
    }
    else {
        file.chunk_size = 0;
        file.file_length = 0;
        file.store = FileTransfer::Store::FIRMWARE;
        file.file_address = 0;
        file.chunk_address = 0;
    }

    

    // check the parameters only
    bool success = !prepare_for_firmware_update(file, 1, NULL);
    if (success) {
        success = file.chunk_count(file.chunk_size) < MAX_CHUNKS;
    }

    last_chunk = file.chunk_count(OTA_CHUNK_SIZE)-1;

    coded_ack(msg_to_send+2, success ? 0x00 : RESPONSE_CODE(4,00), queue[2], queue[3]);
    if (0 > blocking_send(msg_to_send, 18))
    {
      // error
      return false;
    }
    if (success)
    {
        if (!prepare_for_firmware_update(file, 0, NULL))
        {
            #ifdef DEBUG_SETUP
              Serial.println("F1");
            #endif
            last_chunk_millis = millis();
            chunk_index = 0;
            chunk_size = file.chunk_size;   // save chunk size since the descriptor size is overwritten
            updating = 1;
            
            // when not in fast OTA mode, the chunk missing buffer is set to 1 since the protocol
            // handles missing chunks one by one. Also we don't know the actual size of the file to
            // know the correct size of the bitmap.
            set_chunks_received(flags & 1 ? 0 : 0xFF);
            // send update_reaady - use fast OTA if available
            #ifdef DEBUG_SETUP
              Serial.println("F2");
            #endif
            update_ready(msg_to_send + 2, message.token, (flags & 0x1));
            if (0 > blocking_send(msg_to_send, 18))
            {
              // error
            #ifdef DEBUG_SETUP
              Serial.println("F3");
            #endif
              return false;

            }
            #ifdef DEBUG_SETUP
              Serial.println("F4");
            #endif
            if (deviceConfig->system_version < OAK_SYSTEM_VERSION_INTEGER || deviceConfig->system_update_pending > 0){
              if(deviceConfig->system_update_pending == 0){
                deviceConfig->system_update_pending = 1;
                writeDeviceConfig();
              }
              else if(deviceConfig->system_update_pending == 1){
                set_oakboot_defaults(0);
                deviceConfig->system_update_pending = 2;
                writeDeviceConfig();
              }
              else{
                reboot_to_fallback_updater();
              }

            }
            spark_send_event("oak/device/stderr","OTA Update Started", 60, PRIVATE, NULL); 
        }
    }

    //PUMP ONLY CLOUD WHIE UPDATING
    uint32_t update_timeout = millis()+360000;//todo need to find a max for this?
    while(updating>0 && millis()<update_timeout){
      spark_process(false);
    }
    //should never get here
    ESP.restart();
    return true;
}

void spark_disconnect(){
  if(pClient.connected())
    pClient.stop();
}

void spark_delay(uint32_t ms){
  uint32_t start = millis();
  while((millis()-start)<ms){
    spark_process(false);
  }
}

int finish_firmware_update(FileTransfer::Descriptor& file, uint32_t flags, void* reserved)
{

    #ifdef DEBUG_SETUP
  Serial.println("UPDATE FINISHED - REBOOT ME");

#endif
    if (flags & 1) {    // update successful

        if((file.chunk_address/SECTOR_SIZE)<((file.file_address+FLASH_MAX_SIZE)/SECTOR_SIZE)-1){ 
        //check if sector of final chunk is less then the max sector
          noInterrupts();
          spi_flash_erase_sector((file.chunk_address/SECTOR_SIZE)+1);
          interrupts();
        }

        // check CRC and fall through if it fails
        if(check_image(getOTAFlashSlot())){

          deviceConfig->ota_success = 1;
          writeDeviceConfig();

          spark_send_event("oak/device/stderr","OTA Update Complete", 60, PRIVATE, NULL); 
          delay(500);

          #ifdef DEBUG_SETUP
  Serial.println("DONE - RESTART");

#endif
          //set program rom equal to config rom, so that we return to failsafe on failure
          bootConfig->current_rom = getOTAFlashSlot();
          bootConfig->ota_reboot = 1;
          writeBootConfig();
          spark_disconnect();
          delay(100);
          ESP.restart();
          while(1);
        }
        
    }

    spark_send_event("oak/device/stderr","OTA Update Failed", 60, PRIVATE, NULL); 
    delay(500);
    spark_disconnect();
    delay(100);
    ESP.restart();
    
    return 0;
}

bool flash_erase_sector(uint32_t sector){
  return (spi_flash_erase_sector(sector) == SPI_FLASH_RESULT_OK);
}

bool is_claimed(void){
  return deviceConfig->claimed == 1;
}

uint8_t current_rom(void){
  return bootConfig->current_rom;
}
uint8_t config_rom(void){
  return bootConfig->config_rom;
}
uint8_t user_rom(void){
  return bootConfig->program_rom;
}
uint8_t update_rom(void){
  return bootConfig->update_rom;
}
uint8_t ota_reboot(void){
  return bootConfig->ota_reboot;
}

void save_firmware_chunk(FileTransfer::Descriptor& file, uint8_t* chunk, void* reserved)
{

   #ifdef DEBUG_SETUP
              Serial.println("S1");
            #endif
    //todo ensure chunk is 512, else pad to 512 to ensure alignment
    //noInterrupts();
    if(file.chunk_address%SECTOR_SIZE == 0){
      if(spi_flash_erase_sector(file.chunk_address/SECTOR_SIZE) != SPI_FLASH_RESULT_OK){
         #ifdef DEBUG_SETUP
              Serial.println("SF");
            #endif
      }
    }
 #ifdef DEBUG_SETUP
              Serial.println(file.chunk_address);
            #endif
              
              memcpy(chunk_buffer,chunk,512);
    spi_flash_write(file.chunk_address, reinterpret_cast<uint32_t*>(chunk_buffer), OTA_CHUNK_SIZE);
    //interrupts();
     #ifdef DEBUG_SETUP
              Serial.println("S2");
            #endif

    LED_Toggle();

    return;
}


inline void flag_chunk_received(chunk_index_t idx)
{
//    serial_dump("flagged chunk %d", idx);
    chunk_bitmap()[idx>>3] |= uint8_t(1<<(idx&7));
}

void notify_update_done(uint8_t* buf)
{
    unsigned short message_id = next_message_id();
    size_t size = Messages::update_done(buf+2, message_id, false);
    wrap(buf, size);
}

bool handle_chunk(msg& message)
{
  //Serial.println("CHUNK");
    last_chunk_millis = millis();

    uint8_t* msg_to_send = message.response;
    // send ACK
    *msg_to_send = 0;
    *(msg_to_send + 1) = 16;
    empty_ack(msg_to_send + 2, queue[2], queue[3]);
    if (0 > blocking_send(msg_to_send, 18))
    {
      // error
      return false;
    }
    //serial_dump("chunk");
    if (!updating) {
        //serial_dump("got chunk when not updating");
        return true;
    }

    bool fast_ota = false;
    uint8_t payload = 7;

    unsigned option = 0;
    uint32_t given_crc = 0;
    while (queue[payload]!=0xFF) {
        switch (option) {
            case 0:
                given_crc = decode_uint32(queue+payload+1);
                break;
            case 1:
                chunk_index = decode_uint16(queue+payload+1);
                fast_ota = true;
                break;
        }
        option++;
        payload += (queue[payload]&0xF)+1;  // increase by the size. todo handle > 11
    }
    if (0xFF==queue[payload])
    {
        payload++;
        uint8_t* chunk = queue+payload;
        file.chunk_size = message.len - payload - queue[message.len - 1];   // remove length added due to pkcs #7 padding?
        file.chunk_address  = file.file_address + (chunk_index * chunk_size);
        if (chunk_index>=MAX_CHUNKS) {
            //serial_dump("invalid chunk index %d", chunk_index);
            return false;
        }
        uint32_t crc = crc32(chunk, file.chunk_size);
        bool has_response = false;
        bool crc_valid = (crc == given_crc);
 #ifdef DEBUG_SETUP
              Serial.println("C0");
            #endif
        #ifdef DEBUG_SETUP
  Serial.printf("chunk idx=%d crc=%d fast=%d updating=%d", chunk_index, crc_valid, fast_ota, updating);

#endif
   #ifdef DEBUG_SETUP
              Serial.println("C00");
            #endif
        if (crc_valid)
        {

          #ifdef DEBUG_SETUP
              Serial.println("C1");
            #endif

            save_firmware_chunk(file, chunk, NULL);
            if (!fast_ota || (updating!=2 && (true || (chunk_index & 32)==0))) {
                chunk_received(msg_to_send + 2, message.token, ChunkReceivedCode::OK);
                has_response = true;
            }
             #ifdef DEBUG_SETUP
              Serial.println("C2");
            #endif
            flag_chunk_received(chunk_index);
            if (updating==2) {                      // clearing up missed chunks at the end of fast OTA
                chunk_index_t next_missed = next_chunk_missing(0);
                if (next_missed==NO_CHUNKS_MISSING) {
                    #ifdef DEBUG_SETUP
              Serial.println("NO MISS");
            #endif
                    notify_update_done(msg_to_send);
                    finish_firmware_update(file, 1, NULL);
                    
                    has_response = true;
                }
                else {
                    if (has_response && 0 > blocking_send(msg_to_send, 18)) {

                        //serial_dump("send chunk response failed");
                        return false;
                    }
                    has_response = false;

                    if (next_missed>missed_chunk_index)
                        send_missing_chunks(MISSED_CHUNKS_TO_SEND);
                }
            }
            chunk_index++;
        }
        else if (!fast_ota)
        {
           #ifdef DEBUG_SETUP
              Serial.println("C3");
            #endif
            chunk_received(msg_to_send + 2, message.token, ChunkReceivedCode::BAD);
            has_response = true;
            //serial_dump("chunk bad %d", chunk_index);
        }
        // fast OTA will request the chunk later
#ifdef DEBUG_SETUP
              Serial.println("C4");
            #endif
        if (has_response && 0 > blocking_send(msg_to_send, 18))
        {
          #ifdef DEBUG_SETUP
              Serial.println("C5");
            #endif
          // error
          return false;
        }
    }

    return true;
}




bool handle_update_done(msg& message)
{
    // send ACK 2.04
    uint8_t* msg_to_send = message.response;

    *msg_to_send = 0;
    *(msg_to_send + 1) = 16;
    #ifdef DEBUG_SETUP
  Serial.println("update done received");

#endif
    chunk_index_t index = next_chunk_missing(0);
    bool missing = index!=NO_CHUNKS_MISSING;
    coded_ack(msg_to_send + 2, message.token, missing ? ChunkReceivedCode::BAD : ChunkReceivedCode::OK, queue[2], queue[3]);
    if (0 > blocking_send(msg_to_send, 18))
    {
        // error
        return false;
    }

    if (!missing) {
        #ifdef DEBUG_SETUP
  Serial.println("update done - all done!");

#endif
        finish_firmware_update(file, 1, NULL);
    }
    else {
        updating = 2;       // flag that we are sending missing chunks.
        #ifdef DEBUG_SETUP
  Serial.println("update done - missing chunks");

#endif
        send_missing_chunks(MISSED_CHUNKS_TO_SEND);
        last_chunk_millis = millis();
    }
    return true;
}








bool handle_message(msg& message, token_t token, CoAPMessageType::Enum message_type)
{
  switch (message_type)
  {

    case CoAPMessageType::DESCRIBE:
    {
        if (!send_description(DESCRIBE_SYSTEM, message) || !send_description(DESCRIBE_APPLICATION, message)) {
            return false;
        }
        break;
    }
    case CoAPMessageType::FUNCTION_CALL:
        if (!handle_function_call(message))
            return false;
        break;
    case CoAPMessageType::VARIABLE_REQUEST:
    {
      // copy the variable key
      int variable_key_length = queue[7] & 0x0F;
      if (12 < variable_key_length)
        variable_key_length = 12;

      char variable_key[13];
      memcpy(variable_key, queue + 8, variable_key_length);
      memset(variable_key + variable_key_length, 0, 13 - variable_key_length);

      queue[0] = 0;
      queue[1] = 16; // default buffer length

      // get variable value according to type using the descriptor
      SparkReturnType::Enum var_type = wrapVarTypeInEnum(variable_key);
      if(SparkReturnType::BOOLEAN == var_type)
      {
        bool *bool_val = (bool *)getUserVar(variable_key);
        variable_value(queue + 2, token, queue[2], queue[3], *bool_val);
      }
      else if(SparkReturnType::INT == var_type)
      {
        int *int_val = (int *)getUserVar(variable_key);
        variable_value(queue + 2, token, queue[2], queue[3], *int_val);
      }
      else if(SparkReturnType::STRING == var_type)
      {
        char *str_val = (char *)getUserVar(variable_key);

        // 2-byte leading length, 16 potential padding bytes
        int max_length = QUEUE_SIZE - 2 - 16;
        int str_length = strlen(str_val);
        if (str_length > max_length) {
          str_length = max_length;
        }

        int buf_size = variable_value(queue + 2, token, queue[2], queue[3], str_val, str_length);
        queue[1] = buf_size & 0xff;
        queue[0] = (buf_size >> 8) & 0xff;
      }
      else if(SparkReturnType::DOUBLE == var_type)
      {
        double *double_val = (double *)getUserVar(variable_key);
        variable_value(queue + 2, token, queue[2], queue[3], *double_val);
      }

      // buffer length may have changed if variable is a long string
      if (0 > blocking_send(queue, (queue[0] << 8) + queue[1] + 2))
      {
        // error
        return false;
      }
      break;
    }

    case CoAPMessageType::SAVE_BEGIN:
      // fall through
    case CoAPMessageType::UPDATE_BEGIN:
       return handle_update_begin(message);

    case CoAPMessageType::CHUNK:
       return handle_chunk(message);

    case CoAPMessageType::UPDATE_DONE:
       return handle_update_done(message);

    case CoAPMessageType::EVENT:
        handle_event(message);
          break;
    case CoAPMessageType::KEY_CHANGE:
      // TODO
      break;

    case CoAPMessageType::SIGNAL_START:
      queue[0] = 0;
      queue[1] = 16;
      coded_ack(queue + 2, token, ChunkReceivedCode::OK, queue[2], queue[3]);
      if (0 > blocking_send(queue, 18))
      {
        // error
        return false;
      }

      //callbacks.signal(true, 0, NULL);
      break;
    case CoAPMessageType::SIGNAL_STOP:
      queue[0] = 0;
      queue[1] = 16;
      coded_ack(queue + 2, token, ChunkReceivedCode::OK, queue[2], queue[3]);
      if (0 > blocking_send(queue, 18))
      {
        // error
        return false;
      }

      //callbacks.signal(false, 0, NULL);
      break;

    case CoAPMessageType::HELLO:
      if(deviceConfig->ota_success == 1){
        deviceConfig->ota_success = 0;
        writeDeviceConfig();
      }
      break;

    case CoAPMessageType::TIME:
      handle_time_response(queue[6] << 24 | queue[7] << 16 | queue[8] << 8 | queue[9]);
      break;

    case CoAPMessageType::PING:
      queue[0] = 0;
      queue[1] = 16;
      empty_ack(queue + 2, queue[2], queue[3]);
      if (0 > blocking_send(queue, 18))
      {
        // error
        return false;
      }
      break;

    case CoAPMessageType::EMPTY_ACK:
    case CoAPMessageType::ERROR:
    default:
      ; // drop it on the floor
  }

  // all's well
  return true;
}

CoAPMessageType::Enum received_message(unsigned char *buf, size_t length)
{
  unsigned char next_iv[16];
  memcpy(next_iv, buf, 16);

  aes_setkey_dec(&aes, key, 128);
  aes_crypt_cbc(&aes, AES_DECRYPT, length, iv_receive, buf, buf);

  memcpy(iv_receive, next_iv, 16);

  return Messages::decodeType(buf, length);
}



CoAPMessageType::Enum handle_received_message(void)
{
  last_message_millis = millis();
  expecting_ping_ack = false;
  size_t len = queue[0] << 8 | queue[1];
  if (len > QUEUE_SIZE) { // TODO add sanity check on data, e.g. CRC
      return CoAPMessageType::ERROR;
  }
  if (0 > blocking_receive(queue, len))
  {
    // error
    return CoAPMessageType::ERROR;;
  }
  CoAPMessageType::Enum message_type = received_message(queue, len);

  unsigned char token = queue[4];
  unsigned char *msg_to_send = queue + len;

  msg message;
  message.len = len;
  message.token = queue[4];
  message.response = msg_to_send;
  message.response_len = QUEUE_SIZE-len;

  return handle_message(message, token, message_type)
          ? message_type : CoAPMessageType::ERROR;
}


// Returns true if no errors and still connected.
// Returns false if there was an error, and we are probably disconnected.
bool event_loop(CoAPMessageType::Enum& message_type)
{
    message_type = CoAPMessageType::NONE;
  int bytes_received = receive(queue, 2);
  if (2 <= bytes_received)
  {
    message_type = handle_received_message();
    if (message_type==CoAPMessageType::ERROR)
    {
        if (updating) {      // was updating but had an error, inform the client
          #ifdef DEBUG_SETUP
              Serial.println("up error");
            #endif
            finish_firmware_update(file, 0, NULL);
            updating = false;
        }

      // bail if and only if there was an error
 #ifdef DEBUG_SETUP
  INFO("UPDATE ERROR");
#endif
      return false;
    }
  }
  else
  {
    if (0 > bytes_received)
    {
      // error, disconnected
#ifdef DEBUG_SETUP
  INFO("DISCONNECT");
#endif
      return false;
    }

    if (updating)
    {
      uint32_t millis_since_last_chunk = millis() - last_chunk_millis;
      if (3000 < millis_since_last_chunk)
      {
          if (updating==2) {    // send missing chunks
              //serial_dump("timeout - resending missing chunks");
              if (!send_missing_chunks(MISSED_CHUNKS_TO_SEND)){
                 #ifdef DEBUG_SETUP
  INFO("CHUNK ERROR");
#endif
                  return false;
                }
          }
          /* Do not resend chunks since this can cause duplicates on the server.
          else
          {
            queue[0] = 0;
            queue[1] = 16;
            chunk_missed(queue + 2, chunk_index);
            if (0 > blocking_send(queue, 18))
            {
              // error
              return false;
            }
          }
          */
          last_chunk_millis = millis();
      }
    }
    else
    {
      uint32_t millis_since_last_message = millis() - last_message_millis;
      if (expecting_ping_ack)
      {
        if (10000 < millis_since_last_message)
        {
          // timed out, disconnect
          expecting_ping_ack = false;
          last_message_millis = millis();
          #ifdef DEBUG_SETUP
  ERROR("FAILED4");
#endif
          return false;
        }
      }
      else
      {
        if (15000 < millis_since_last_message)
        {
          queue[0] = 0;
          queue[1] = 16;
          ping(queue + 2);
          blocking_send(queue, 18);

          expecting_ping_ack = true;
          last_message_millis = millis();
        }
      }
    }
  }

  // no errors, still connected

  return true;
}

bool event_loop(CoAPMessageType::Enum message_type, uint32_t timeout)
{
    uint32_t start = millis();
    do
    {
        CoAPMessageType::Enum msgtype;
        if (!event_loop(msgtype))
            return false;
        if (msgtype==message_type)
            return true;
        // todo - ideally need a delay here
    }
    while ((millis()-start) < timeout);
    return false;
}


bool event_loop()
  {
    CoAPMessageType::Enum message;
    return event_loop(message);
  }


int handshake(){

   #ifdef DEBUG_SETUP
  INFO("SHAKE");
#endif  
  #ifdef DEBUG_SETUP
  Serial.println(pClient.status());

#endif
  memcpy(queue + 40, device_id, 12);
  int err = blocking_receive(queue, 40);;
  #ifdef DEBUG_SETUP
  Serial.println(err);

#endif
  if (0 > err) { 
    #ifdef DEBUG_SETUP
  ERROR("Handshake: could not receive nonce");
#endif  
    return err; 
  }

  memcpy(queue+52, deviceConfig->device_public_key,PUBLIC_KEY_LENGTH);

   #ifdef DEBUG_SETUP
  INFO("SHAKE1");
#endif  

  rsa_context rsa;
  init_rsa_context_with_public_key(&rsa, deviceConfig->server_public_key);
  const int len = 52+PUBLIC_KEY_LENGTH;
  err = rsa_pkcs1_encrypt(&rsa, RSA_PUBLIC, len, queue, queue + len);
  rsa_free(&rsa);

  if (err) { 
    #ifdef DEBUG_SETUP
  ERROR("Handshake: rsa encrypt error");
#endif 
    return err; }

  #ifdef DEBUG_SETUP
  Serial.println(pClient.status());

#endif

     #ifdef DEBUG_SETUP
  INFO("SHAKE2");
#endif  

  err = blocking_send(queue + len, 256);
     #ifdef DEBUG_SETUP
  INFO("SHAKE3");
#endif  
  if (0 > err) { 
  #ifdef DEBUG_SETUP
  Serial.println(pClient.status());

#endif 
  #ifdef DEBUG_SETUP
  ERROR("Handshake: Unable to send key");
#endif 
  return err;
}

   #ifdef DEBUG_SETUP
  INFO("SHAKE4");
#endif  

  err = blocking_receive(queue, 384);
  if (0 > err) { 
    #ifdef DEBUG_SETUP
  ERROR("Handshake: Unable to receive key");
#endif 
    return err; }

        #ifdef DEBUG_SETUP
  INFO("SET KEY");
#endif  

  err = set_key(queue);
  if (err) { 
    #ifdef DEBUG_SETUP
  ERROR("Handshake:  could not set key");
#endif 
    return err; }

    #ifdef DEBUG_SETUP
  INFO("SEND HELLO");
#endif  

  //gets reset on response in handle message
  hello(queue, deviceConfig->ota_success);

      #ifdef DEBUG_SETUP
  INFO("GET HELLO RESPONSE");
#endif  

  err = blocking_send(queue, 18);
  if (0 > err) { 
    #ifdef DEBUG_SETUP
  ERROR("Hanshake: could not send hello message");
#endif 
    return err; }

        #ifdef DEBUG_SETUP
  INFO("WAIT FOR SERVER HELLO");
#endif  

  if (!event_loop(CoAPMessageType::HELLO, 2000))        // read the hello message from the server
  {
    #ifdef DEBUG_SETUP
  ERROR("Handshake: could not receive hello response");
#endif
    return -1;
  }
  #ifdef DEBUG_SETUP
  INFO("Hanshake: completed");
#endif
  return 0;
}






void remove_event_handlers(const char* event_name)
{
    if (NULL == event_name)
    {
        memset(event_handlers, 0, sizeof(event_handlers));
    }
    else
    {
        const int NUM_HANDLERS = sizeof(event_handlers) / sizeof(FilteringEventHandler);
        int dest = 0;
        for (int i = 0; i < NUM_HANDLERS; i++)
        {
          if (!strcmp(event_name, event_handlers[i].filter))
          {
              memset(&event_handlers[i], 0, sizeof(event_handlers[i]));
          }
          else
          {
              if (dest!=i) {
                memcpy(event_handlers+dest, event_handlers+i, sizeof(event_handlers[i]));
                memset(event_handlers+i, 0, sizeof(event_handlers[i]));
              }
              dest++;
          }
        }
    }
}




bool particleConnect(){
  if(deviceConfig->server_address_type == 1){
    return pClient.connect(deviceConfig->server_address_domain,SPARK_SERVER_PORT);
    //return pClient.connect("staging-device.spark.io",SPARK_SERVER_PORT);
    //return pClient.connect(IPAddress(192,168,0,111),SPARK_SERVER_PORT);
  }
  else{
    return pClient.connect(IPAddress(deviceConfig->server_address_ip),SPARK_SERVER_PORT); 
  }
}


//this connects to the configured wifi
bool wifiConnect(){
  WiFi.softAPdisconnect(false);
  WiFi.mode(WIFI_STA);
  if(deviceConfig->passcode[0] != '\0' && deviceConfig->channel > 0){
    WiFi.begin(deviceConfig->ssid,deviceConfig->passcode, deviceConfig->channel);
  }
  else if(deviceConfig->passcode[0] != '\0'){
    WiFi.begin(deviceConfig->ssid,deviceConfig->passcode);
  }
  else if(deviceConfig->channel > 0){
    WiFi.begin(deviceConfig->ssid, NULL, deviceConfig->channel);
  }
  else if (deviceConfig->ssid[0] != '\0'){
    WiFi.begin(deviceConfig->ssid);
  }
  else{
    return false;
  }
  return true;
}

bool wifiConnected(){
  return (WiFi.status() == WL_CONNECTED);
}





bool wifiWaitForConnection(){ //returns false if it times out - I will later add code to jump to config rom in this case
  uint32_t timeoutTime = millis() + 15000;
  while (WiFi.status() != WL_CONNECTED)
  {
    yield();
    //timeout after 15 seconds
    if(millis() > timeoutTime){
        return false;
    }
  }
  return true;
}




bool readDeviceConfig(bool isSystem){
  noInterrupts();
  spi_flash_read(DEVICE_CONFIG_SECTOR * SECTOR_SIZE, reinterpret_cast<uint32_t*>(config_buffer), DEVICE_CONFIG_SIZE);

  if(deviceConfig->magic != DEVICE_MAGIC || deviceConfig->chksum != calc_device_chksum((uint8*)deviceConfig, (uint8*)&deviceConfig->chksum)){
  //load the backup and copy to main
  spi_flash_read(DEVICE_BACKUP_CONFIG_SECTOR * SECTOR_SIZE, reinterpret_cast<uint32_t*>(config_buffer), DEVICE_CONFIG_SIZE);
  spi_flash_erase_sector(DEVICE_CONFIG_SECTOR);
  spi_flash_write(DEVICE_CONFIG_SECTOR * SECTOR_SIZE, reinterpret_cast<uint32_t*>(config_buffer), DEVICE_CONFIG_SIZE);
  }
  interrupts();

  if(deviceConfig->magic != DEVICE_MAGIC || deviceConfig->chksum != calc_device_chksum((uint8*)deviceConfig, (uint8*)&deviceConfig->chksum)){
      if(isSystem){
        ets_memset(deviceConfig, 0x00, sizeof(oak_config));
        deviceConfig->magic = DEVICE_MAGIC;
        deviceConfig->chksum = calc_device_chksum((uint8*)deviceConfig, (uint8*)&deviceConfig->chksum);
        writeDeviceConfig();
      }
      else{
       reboot_to_config();
       return false;
     }
  }

  return true;
}









unsigned char next_token()
{
  return ++_token;
}

size_t time_request(unsigned char *buf)
{
    uint16_t msg_id = next_message_id();
    uint8_t token = next_token();
    return Messages::time_request(buf, msg_id, token);
}


bool send_time_request(void)
{
  if (updating)
  {
    return false;
  }

  size_t msglen = time_request(queue + 2);
  size_t wrapped_len = wrap(queue, msglen);
  last_chunk_millis = millis();

  return (0 <= blocking_send(queue, wrapped_len));
}

bool particle_handshake(){

  char buf[65];
#ifdef DEBUG_SETUP
  INFO("START HANDSHAKE");
#endif
  if(handshake()<0)
    return false;
#ifdef DEBUG_SETUP
  INFO("END HANDSHAKE");
#endif
  #ifdef DEBUG_SETUP
  INFO("SEND EVENTS");
#endif
  if(deviceConfig->claim_code[0] != '\0')
    spark_send_event("spark/device/claim/code", deviceConfig->claim_code, 60, PRIVATE, NULL);

  //send max size of rom
  ultoa(FLASH_MAX_SIZE, buf, 10);
  spark_send_event("spark/hardware/max_binary", buf, 60, PRIVATE, NULL);

  //send ota chunk size
  ultoa(OTA_CHUNK_SIZE, buf, 10);
  spark_send_event("spark/hardware/ota_chunk_size", buf, 60, PRIVATE, NULL);

  ///if we want to be able to get a system update we need to send that we are in safe more right now
  if (deviceConfig->system_version < OAK_SYSTEM_VERSION_INTEGER || deviceConfig->system_update_pending > 0){
    spark_send_event("spark/device/safemode" "", "", 60, PRIVATE, NULL);
  }

/*
  #if defined(SPARK_SUBSYSTEM_EVENT_NAME)
    if (!HAL_core_subsystem_version(buf, sizeof (buf)) && *buf)
    {
        spark_send_event("spark/" SPARK_SUBSYSTEM_EVENT_NAME, buf, 60, PRIVATE, NULL);
    }
  #endif
*/
  #ifdef DEBUG_SETUP
  INFO("SEND SUBS");
#endif

  send_subscriptions();
  // important this comes at the end since it requires a response from the cloud.
  #ifdef DEBUG_SETUP
  INFO("SEND TIME REQ");
#endif
  send_time_request();
  #ifdef DEBUG_SETUP
  INFO("LOOP");
#endif
  if(!event_loop()){
    #ifdef DEBUG_SETUP
  ERROR("SHAKE LOOP FAIL");
#endif
  }
  return true;
}




void reboot_to_user(){
  if(bootConfig->current_rom != bootConfig->program_rom)
    bootConfig->current_rom = bootConfig->program_rom;
  ESP.restart();
  while(1);
}

void reboot_to_config(){
  if(bootConfig->current_rom != bootConfig->config_rom)
    bootConfig->current_rom = bootConfig->config_rom;
  ESP.restart();
  while(1);
}

void reboot_to_fallback_updater(){
  if(bootConfig->current_rom != bootConfig->update_rom)
    bootConfig->current_rom = bootConfig->update_rom;
  ESP.restart();
  while(1);
}

String spark_deviceID(){
  return String(deviceConfig->device_id);
}

const char* CLAIM_EVENTS = "spark/device/claim/";
const char* RESET_EVENT = "spark/device/reset";
const char* OAK_RESET_EVENT = "oak/device/reset";
const char* OAK_RX_EVENT = "oak/device/stdin";

void SystemEvents(const char* name, const char* data)
{
    if (!strncmp(name, CLAIM_EVENTS, strlen(CLAIM_EVENTS))) {
        //mark as claimed
        deviceConfig->claim_code[0] != '\0';
        deviceConfig->claimed = 1;
        writeDeviceConfig();
    }
    if (!strcmp(name, RESET_EVENT)) {
        if (data && *data) {
            if (!strcmp("safe mode", data))
                reboot_to_config();
            else if (!strcmp("dfu", data))
              return;
            else if (!strcmp("reboot", data))
                ESP.reset();
        }
    }
    if (!strcmp(name, OAK_RESET_EVENT)) {
        if (data && *data) {
            if (!strcmp("config mode", data))
                reboot_to_config();
            else if (!strcmp("user mode", data))
                reboot_to_user();
            else if (!strcmp("update mode", data))
                reboot_to_fallback_updater();
            else if (!strcmp("reboot", data))
                ESP.reset();
        }
    }
    if (!strcmp(name, OAK_RX_EVENT)) {
        if (data && *data) {
            /*
            while(*data != '\0'){
              // if buffer full, set the overflow flag and return
              uint8_t next = (spark_receive_buffer_tail + 1) % MAX_BUFF;
              if (next != spark_receive_buffer_head)
              {
                // save new data in buffer: tail points to where byte goes
                spark_receive_buffer[spark_receive_buffer_tail] = *data; // save new byte
                data++;
                spark_receive_buffer_tail = next;
              } 
              else 
              {
                spark_buffer_overflow = true;
                return;
              }
            }
             */
        }
    }
}


bool oak_rom_inited = false;

void oak_rom_init(){
  if(oak_rom_inited)
    return;

  oak_rom_inited = true;
  #ifndef OAK_SYSTEM_ROM_4F616B
    #pragma message "SYSTEM DEFINE NOT SET, DEFAULTING TO USER ROM"
    #define OAK_SYSTEM_ROM_4F616B 0
  #else
    #pragma message "SYSTEM DEFINE SET"
  #endif
  #ifdef OAK_SYSTEM_ROM_4F616B //DO NOT DEFINE THIS IN YOUR FILE OR IT MAY CORRUPT YOUR DEVICE
    if(OAK_SYSTEM_ROM_4F616B == 82 && deviceConfig->system_version < OAK_SYSTEM_VERSION_INTEGER){
      //TODO WHAT ABOUT BOOTING TO THIS DO TO FAILURE AFTER UPDATE
      //this is a new system rom that we just booted into
      deviceConfig->system_version = OAK_SYSTEM_VERSION_INTEGER;

      sprintf(deviceConfig->version_string, "%d.%d.%d", OAK_SYSTEM_VERSION_MAJOR, OAK_SYSTEM_VERSION_MINOR, OAK_SYSTEM_VERSION_RELEASE);
      #ifdef DEBUG_SETUP
        Serial.println(deviceConfig->version_string);
      #endif
      //memcpy(deviceConfig->version_string,OAK_SYSTEM_VERSION_STRING,sizeof(OAK_SYSTEM_VERSION_STRING));
      if(bootConfig->config_rom != bootConfig->current_rom){ 
        bootConfig->ota_reboot = 0;
        bootConfig->config_rom = bootConfig->current_rom;
        bootConfig->update_rom = bootConfig->current_rom+2;
        writeBootConfig();
      }
      deviceConfig->system_update_pending = 0;
      init_bootloader_flags();
      writeDeviceConfig();
      
      //go back to the user application
      reboot_to_user();
    }
    else if(OAK_SYSTEM_ROM_4F616B != 82){

      //dont do this until we reach the end of setup? the end of loop?
      //this is a new user rom, we have booted so set user rom to this
      if(bootConfig->program_rom != bootConfig->current_rom){ //if not already set
        bootConfig->ota_reboot = 0;
        bootConfig->program_rom = bootConfig->current_rom;
        writeBootConfig();
      }
      init_bootloader_flags();
    }
  #endif

}

//this should be called when the Particle library is inited 
void spark_initConfig(bool isSystem){
  if(spark_initialized)
    return;
  spark_initialized = true;
  #ifdef DEBUG_SETUP
  Serial.println("INIT CONFIG");

#endif
  readDeviceConfig(isSystem); //will not return if valid device config does not exist, will reboot to config ROM, unless isSytem in which case it will create a new one
  readBootConfig();
  hex_decode(device_id,12,deviceConfig->device_id);
  spark_subscribe("spark", SystemEvents, NULL, ALL_DEVICES, NULL, NULL);
  spark_subscribe("oak", SystemEvents, NULL, MY_DEVICES, NULL, NULL);
}

uint8_t wifi_connect_failed = 0;

bool spark_internal_connect(){
  if(!spark_initialized)
    spark_initConfig(false);
  spark_connect_pending = true;
  if(!wifiConnected()){
    if(!wifiConnect()){

      //the wifi info is just bad
      reboot_to_config();
      #ifdef DEBUG_SETUP
  Serial.println("WIFI");

#endif
      spark_connect_pending = false;
      return false;
    }
    if(!wifiWaitForConnection()){
      #ifdef DEBUG_SETUP
  Serial.println("WAIT");

#endif
      spark_connect_pending = false;
      wifi_connect_failed++;
      if(wifi_connect_failed>5)
        reboot_to_config();
      return false;
    }
    wifi_connect_failed = 0;
  }
  if(!pClient.connected()){
    if(!particleConnect()){
      #ifdef DEBUG_SETUP
  Serial.println("Particle");

#endif
      spark_connect_pending = false;
      return false;
    }
    else{
      //we just connected
      spark_describe_called = false;
    }
    if(!particle_handshake()){
      #ifdef DEBUG_SETUP
  Serial.println("SHAKE");

#endif
      spark_connect_pending = false;
      return false;
    }

  }
  spark_connect_pending = false;
  return true;
} 

uint8_t spark_failed_connects = 0;
bool spark_ok_to_connect = false;

uint32_t spark_last_failed_connect = 0;

bool spark_auto_connect(bool internal){
  if(internal)
    oak_rom_init();
  if(system_mode>1 && internal)
    return false;

  spark_ok_to_connect = true;
  #ifdef DEBUG_SETUP
    Serial.println("AUTO CONNECT");
  #endif
  while(!spark_connect() && spark_failed_connects < 3){yield();};
  #ifdef DEBUG_SETUP
    Serial.println("END AUTO CONNECT");
  #endif
  if(spark_failed_connects == 3)
    return false;
  else{
    //pump events until describe
    //uint32_t desc_start = millis();
    /*while(!spark_describe_called && millis()-desc_start<3000){
      #ifdef DEBUG_SETUP
    Serial.println("DESC PUMP");
  #endif
      spark_process();
    }*/
    //pump 5 times
    uint8_t pumpLoop = 5;
    while(pumpLoop-->0){
      spark_process();
    }
    return true;
  }

}

bool spark_connect(){
  //connect with automatic back off
  //
  if(spark_failed_connects < 2 || 
    (spark_failed_connects < 5 && millis()-spark_last_failed_connect > 5000) || 
    millis()-spark_last_failed_connect > 30000 ){
    if(!spark_internal_connect()){
      spark_failed_connects++;
      spark_last_failed_connect = millis();
      return false;
    }
    else{
      spark_failed_connects = 0;
      return true;
    }
  }
  return false;
}

void spark_process(bool internal)
{
    if(!internal)
      yield();
    else if(system_mode == 3)
      return;
    if(spark_connect_pending){
        #ifdef DEBUG_SETUP
              ERROR("ALREADY PENDING");
            #endif
      return;
    }
    if(spark_connected()){
        spark_send_tx();
        if(!event_loop()){
            if(pClient.connected()){
              pClient.stop();
            }
            #ifdef DEBUG_SETUP
              ERROR("EVENT LOOP FAIL!");
            #endif
            return;
        }
    }
    else{
      #ifdef DEBUG_SETUP
              ERROR("NO CONNECT");
            #endif
      if(system_mode < 2 || spark_ok_to_connect)
        spark_connect();
      else
        return;
    }
    lastCloudEvent = millis();
}

#define MAX_SERIAL_BUFF 256

char* spark_receive_buffer = NULL;
char* spark_transmit_buffer = NULL;

volatile uint8_t spark_receive_buffer_tail = 0;
volatile uint8_t spark_receive_buffer_head = 0;
volatile uint8_t spark_transmit_buffer_tail = 0;
volatile uint8_t spark_transmit_buffer_head = 0;
volatile uint8_t spark_listening;
volatile uint8_t spark_buffer_overflow;
volatile uint8_t spark_serial_state = 0;

void spark_serial_begin(){
    //don't allocate buffers until this is called
    spark_receive_buffer = new char[MAX_SERIAL_BUFF];
    spark_transmit_buffer = new char[MAX_SERIAL_BUFF];
    if(spark_serial_state == 0){
      spark_subscribe("oak/device/stdin", spark_get_rx, NULL, MY_DEVICES, NULL, NULL);
    }
    spark_serial_state = 2;

}

void spark_serial_end()
{
    //de-allocate buffers here
    delete[] spark_receive_buffer;
    spark_receive_buffer = NULL;
    delete[] spark_transmit_buffer;
    spark_transmit_buffer = NULL;
    spark_serial_state = 1;
}

// Read data from buffer
int spark_serial_read()
{
    // Empty buffer?
    if (spark_receive_buffer_head == spark_receive_buffer_tail)
        return -1;

    // Read from "head"
    uint8_t d = spark_receive_buffer[spark_receive_buffer_head]; // grab next byte
    spark_receive_buffer_head = (spark_receive_buffer_head + 1) % MAX_SERIAL_BUFF;
    return d;
}

int spark_serial_available()
{
    return (spark_receive_buffer_tail + MAX_SERIAL_BUFF - spark_receive_buffer_head) % MAX_SERIAL_BUFF;
}

size_t spark_serial_write(uint8_t b)
{
    // if buffer full, set the overflow flag and return
    uint8_t next = (spark_transmit_buffer_tail + 1) % MAX_SERIAL_BUFF;
    if (next != spark_transmit_buffer_head)
    {
      // save new data in buffer: tail points to where byte goes
      spark_transmit_buffer[spark_transmit_buffer_tail] = b; // save new byte
      spark_transmit_buffer_tail = next;
      return 1;
    } 
    else 
    {
      spark_buffer_overflow = true;
      return 0;
    }
}

void spark_serial_flush()
{
    spark_transmit_buffer_tail = spark_transmit_buffer_head;
}

int spark_serial_peek()
{
    // Empty buffer?
    if (spark_receive_buffer_head == spark_receive_buffer_tail)
        return -1;

    // Read from "head"
    return spark_receive_buffer[spark_receive_buffer_head];
}


void spark_get_rx(const char* name, const char* data){ //this is automatically called when new data comes from the cloud
  if(spark_serial_state < 2){
    return;
  }

    if (data && *data) {

        while(*data != '\0'){
            // if buffer full, set the overflow flag and return
            uint8_t next = (spark_receive_buffer_tail + 1) % MAX_SERIAL_BUFF;
            if (next != spark_receive_buffer_head)
            {
            // save new data in buffer: tail points to where byte goes
                spark_receive_buffer[spark_receive_buffer_tail] = *data; // save new byte
                data++;
                spark_receive_buffer_tail = next;
            } 
            else 
            {
                spark_buffer_overflow = true;
                return;
            }
        }

    }
}

void spark_send_tx(){

    if(spark_transmit_buffer_tail == spark_transmit_buffer_head)//nothing buffer
        return;
    uint8_t buffer_length = (spark_transmit_buffer_tail + MAX_SERIAL_BUFF - spark_transmit_buffer_head) % MAX_SERIAL_BUFF;
    char buff[buffer_length];

    for(uint8_t b;b<buffer_length;b++){
        // Read from "head"
        buff[b] = spark_transmit_buffer[spark_transmit_buffer_head]; // grab next byte
        spark_transmit_buffer_head = (spark_transmit_buffer_head + 1) % MAX_SERIAL_BUFF;
    }

    spark_send_event("oak/device/stdout", buff, 60, PRIVATE, NULL);
}







#define NOINLINE __attribute__ ((noinline))

#define ROM_MAGIC    0xe9
#define ROM_MAGIC_NEW1 0xea
#define ROM_MAGIC_NEW2 0x04


// buffer size, must be at least 0x10 (size of rom_header_new structure)
#define BUFFER_SIZE 0x100

// functions we'll call by address
typedef void stage2a(uint32);
typedef void usercode(void);

// standard rom header
typedef struct {
  // general rom header
  uint8 magic;
  uint8 count;
  uint8 flags1;
  uint8 flags2;
  usercode* entry;
} rom_header;

typedef struct {
  uint8* address;
  uint32 length;
} section_header;

// new rom header (irom section first) there is
// another 8 byte header straight afterward the
// standard header
typedef struct {
  // general rom header
  uint8 magic;
  uint8 count; // second magic for new header
  uint8 flags1;
  uint8 flags2;
  uint32 entry;
  // new type rom, lib header
  uint32 add; // zero
  uint32 len; // length of irom section
} rom_header_new;


bool check_image(uint8_t rom_number) {

  uint32 readpos = bootConfig->roms[rom_number];
  
  uint8 buffer[BUFFER_SIZE];
  uint8 sectcount;
  uint8 sectcurrent;
  uint8 *writepos;
  uint8 chksum = CHKSUM_INIT;
  uint32 loop;
  uint32 remaining;
  uint32 romaddr;
  
  rom_header_new *header = (rom_header_new*)buffer;
  section_header *section = (section_header*)buffer;
  
  if (readpos == 0 || readpos == 0xffffffff) {
    //ets_printf("EMPTY");
    return 0;
  }
  
  // read rom header
  //if (SPIRead(readpos, header, sizeof(rom_header_new)) != 0) {
  if (spi_flash_read(readpos, reinterpret_cast<uint32_t*>(header), sizeof(rom_header_new)) != SPI_FLASH_RESULT_OK) {
    //ets_printf("NO_HEADER");
    return 0;
  }
  
  // check header type
  if (header->magic == ROM_MAGIC) {
    // old type, no extra header or irom section to skip over
    romaddr = readpos;
    readpos += sizeof(rom_header);
    sectcount = header->count;
  } else if (header->magic == ROM_MAGIC_NEW1 && header->count == ROM_MAGIC_NEW2) {
    // new type, has extra header and irom section first
    romaddr = readpos + header->len + sizeof(rom_header_new);

    // we will set the real section count later, when we read the header
    sectcount = 0xff;
    // just skip the first part of the header
    // rest is processed for the chksum
    readpos += sizeof(rom_header);
/*
    // skip the extra header and irom section
    readpos = romaddr;
    // read the normal header that follows
    if (SPIRead(readpos, header, sizeof(rom_header)) != 0) {
      //ets_printf("NNH");
      return 0;
    }
    sectcount = header->count;
    readpos += sizeof(rom_header);
*/
  } else {
    //ets_printf("BH");
    return 0;
  }
  
  // test each section
  for (sectcurrent = 0; sectcurrent < sectcount; sectcurrent++) {
    //ets_printf("ST");
    
    // read section header
    if (spi_flash_read(readpos, reinterpret_cast<uint32_t*>(section), sizeof(section_header)) != SPI_FLASH_RESULT_OK) {
      return 0;
    }
    readpos += sizeof(section_header);

    // get section address and length
    writepos = section->address;
    remaining = section->length;
    
    while (remaining > 0) {
      // work out how much to read, up to BUFFER_SIZE
      uint32 readlen = (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE;
      // read the block
      if (spi_flash_read(readpos, reinterpret_cast<uint32_t*>(buffer), readlen) != SPI_FLASH_RESULT_OK) {
        return 0;
      }
      // increment next read and write positions
      readpos += readlen;
      writepos += readlen;
      // decrement remaining count
      remaining -= readlen;
      // add to chksum
      for (loop = 0; loop < readlen; loop++) {
        chksum ^= buffer[loop];
      }
    }
    
//#ifdef BOOT_IROM_CHKSUM
    if (sectcount == 0xff) {
      // just processed the irom section, now
      // read the normal header that follows
      if (spi_flash_read(readpos, reinterpret_cast<uint32_t*>(header), sizeof(rom_header)) != SPI_FLASH_RESULT_OK) {
        //ets_printf("SPI");
        return 0;
      }
      sectcount = header->count + 1;
      readpos += sizeof(rom_header);
    }
//#endif
  }
  
  // round up to next 16 and get checksum
  readpos = readpos | 0x0f;

  if (spi_flash_read(readpos, reinterpret_cast<uint32_t*>(buffer), 1) != SPI_FLASH_RESULT_OK) {
    //ets_printf("CK");
    return 0;

  }
  
  // compare calculated and stored checksums
  if (buffer[0] != chksum) {
    //ets_printf("CKF");
    return 0;
  }
  
  return 1;
}

int decrypt_rsa(const uint8_t* ciphertext, const uint8_t* private_key, uint8_t* plaintext, int plaintext_len)
{
    rsa_context rsa;
    init_rsa_context_with_private_key(&rsa, private_key);
    int err = rsa_pkcs1_decrypt(&rsa, RSA_PRIVATE, &plaintext_len, ciphertext, plaintext, plaintext_len);
    rsa_free(&rsa);
    return err ? -abs(err) : plaintext_len;
}


int decrypt(char* plaintext, int max_plaintext_len, char* hex_encoded_ciphertext) {
    const size_t len = 256;
    uint8_t buf[len];
    hex_decode(buf, len, hex_encoded_ciphertext);

    // reuse the hex encoded buffer
    int plaintext_len = decrypt_rsa(buf, deviceConfig->device_private_key, (uint8_t*)plaintext, max_plaintext_len);
    return plaintext_len;
}

/**
 * Reads and generates the device's private key.
 * @param keyBuffer
 * @return
 */
bool generatePrivateKey(uint8_t *keyBuffer)//, bool force)
{
    if(*keyBuffer!=0xFF && *keyBuffer!=0x00){// && !force){
      return false;
    }
    else{
      ESP.wdtDisable();
        if (!gen_rsa_key(keyBuffer, PRIVATE_KEY_LENGTH, rsa_random, NULL)) {
            //keyBuffer + PRIVATE_KEY_LENGTH = '\0';
            ESP.wdtEnable(WDTO_8S);
            return true;
        }
      ESP.wdtEnable(WDTO_8S);
    }
    return false;
}

static char ascii_nibble(uint8_t nibble) {
    char hex_digit = nibble + 48;
    if (57 < hex_digit)
        hex_digit += 7;
    return hex_digit;
}

int rsa_random(void* p)
{
    byte randBytes[4];
    os_get_random(randBytes, 4);
    return *((long *)randBytes);
}

bool IPAddressFromString(IPAddress &ipaddress, const char *address)
{

    uint16_t acc = 0; // Accumulator
    uint8_t dots = 0;

    while (*address)
    {
        char c = *address++;
        if (c >= '0' && c <= '9')
        {
            acc = acc * 10 + (c - '0');
            if (acc > 255) {
                // Value out of [0..255] range
                return false;
            }
        }
        else if (c == '.')
        {
            if (dots == 3) {
                // Too much dots (there must be 3 dots)
                return false;
            }
            ipaddress[dots++] = acc;
            acc = 0;
        }
        else
        {
            // Invalid char
            return false;
        }
    }

    if (dots != 3) {
        // Too few dots (there must be 3 dots)
        return false;
    }
    ipaddress[3] = acc;
    return true;
}


String info_response(void){

  String response = "{\"id\":\"";
  response += deviceConfig->device_id;
  response += "\",\"claimed\":";
  if(deviceConfig->claimed != 1)
    response += "0,";
  else
    response += "1,";
  response += "\"claim_code\":\"";
  response += deviceConfig->claim_code;
  response += "\",\"server_address_type\":";
  if(deviceConfig->server_address_type != 1){
    response += "0,";
    response += "\"server_address_ip\":\"";
    IPAddress server_ip = IPAddress(deviceConfig->server_address_ip);
    response += String(server_ip[0]);
    response += ".";
    response += String(server_ip[1]);
    response += ".";
    response += String(server_ip[2]);
    response += ".";
    response += String(server_ip[3]);
    response += "\"";
  }
  else if(deviceConfig->server_address_type == 1){
    response += "1,";
    response += "\"server_address_domain\":\"";
    response += deviceConfig->server_address_domain;
    response += "\"";
  }
  else
    response += "-1,";

    response += ",\"firmware_version\":";
  response += deviceConfig->firmware_version;
    response += ",\"version_string\":\"";
  response += deviceConfig->version_string;
  response += "\",\"meta_id\":";
  response += deviceConfig->third_party_id;
   response += ",\"meta_data\":\"";
  response += deviceConfig->third_party_data;
  response += "\",\"first_update_domain\":\"";
  response += deviceConfig->first_update_domain;
  response += "\",\"first_update_url\":\"";
  response += deviceConfig->first_update_url;
  response += "\",\"first_update_fingerprint\":\"";
  response += deviceConfig->first_update_fingerprint;
  response += "\"}";
  return response;
}

String set_config_from_JSON(String json){

  String valueString;
  uint8_t gotSomething = false;
  int16_t valueStart = json.indexOf("\"cc\":\"");
  int16_t valueEnd;
  if(valueStart>=0){
    valueEnd = json.indexOf('"',valueStart+6);
    valueString = json.substring(valueStart+6,valueEnd);
    valueString.trim();
    if(valueString.length()<63){
      return String("{\"r\":-1}");
    }
    gotSomething = true;
    valueString.toCharArray(deviceConfig->claim_code,65);
    deviceConfig->claim_code[64] = '\0';
  }

  valueStart = json.indexOf("\"device-id\":\"");
  if(valueStart>=0){
    valueEnd = json.indexOf('"',valueStart+13);
    valueString = json.substring(valueStart+13,valueEnd);
    valueString.trim();
    if(valueString.length()!=24){

      return String("{\"r\":-1}");
    }
    #ifdef DEBUG_SETUP
      Serial.print("=");
      Serial.print(valueString);
      Serial.println("=");
    #endif
    //deviceIdSet = true;
    //bootConfig->first_boot = 1;
    //writeBootConfig();
    //LEDFlip.attach(0.5, FlipLED);
    gotSomething = true;
    valueString.toCharArray(deviceConfig->device_id,25);
    #ifdef DEBUG_SETUP
      Serial.print("=");
      Serial.print(deviceConfig->device_id);
      Serial.println("=");
    #endif
    deviceConfig->device_id[24] = '\0';
    #ifdef DEBUG_SETUP
      Serial.print("=");
      Serial.print(deviceConfig->device_id);
      Serial.println("=");
    #endif
  }

  valueStart = json.indexOf("\"meta-id\":");
  if(valueStart>=0){
    valueEnd = json.indexOf(',',valueStart+10);
    valueString = json.substring(valueStart+10,valueEnd);
    gotSomething = true;
    deviceConfig->third_party_id = valueString.toInt();
  }

  valueStart = json.indexOf("\"first-update-domain\":\"");
  if(valueStart>=0){
    valueEnd = json.indexOf('"',valueStart+23);
    valueString = json.substring(valueStart+23,valueEnd);
    valueString.trim();
    if(valueString.length()>64){
      return String("{\"r\":-1}");
    }
    gotSomething = true;
    valueString.toCharArray(deviceConfig->first_update_domain,valueString.length()+1);
    deviceConfig->first_update_domain[valueString.length()] = '\0';
  }

  valueStart = json.indexOf("\"first-update-url\":\"");
  if(valueStart>=0){
    valueEnd = json.indexOf('"',valueStart+20);
    valueString = json.substring(valueStart+20,valueEnd);
    valueString.trim();
    if(valueString.length()>64){
      return String("{\"r\":-1}");
    }
    gotSomething = true;
    valueString.toCharArray(deviceConfig->first_update_url,valueString.length()+1);
    deviceConfig->first_update_url[valueString.length()] = '\0';
  }

  valueStart = json.indexOf("\"first-update-fingerprint\":\"");
  if(valueStart>=0){
    valueEnd = json.indexOf('"',valueStart+28);
    valueString = json.substring(valueStart+28,valueEnd);
    valueString.trim();
    if(valueString.length()>59){
      return String("{\"r\":-1}");
    }
    gotSomething = true;
    valueString.toCharArray(deviceConfig->first_update_fingerprint,valueString.length()+1);
    deviceConfig->first_update_fingerprint[valueString.length()] = '\0';
  }

  valueStart = json.indexOf("\"meta-data\":\"");
  if(valueStart>=0){
    valueEnd = json.indexOf('"',valueStart+13);
    valueString = json.substring(valueStart+13,valueEnd);
    valueString.trim();
    if(valueString.length()>255){
      return String("{\"r\":-1}");
    }
    gotSomething = true;
    valueString.toCharArray(deviceConfig->third_party_data,valueString.length()+1);
    deviceConfig->third_party_data[valueString.length()] = '\0';
  }

  valueStart = json.indexOf("\"server-address\":\"");
  if(valueStart>=0){
    valueEnd = json.indexOf('"',valueStart+18);
    valueString = json.substring(valueStart+18,valueEnd);
    valueString.trim();
    if(valueString.length()>253){
      return String("{\"r\":-1}");
    }
    //get server address type
    valueStart = json.indexOf("\"server-address-type\":");
    if(valueStart<0){
      //server-address-type not set
      return String("{\"r\":-1}");
    }
    char server_address_type = json.charAt(valueStart+22);
    if(server_address_type == '0'){
      gotSomething = true;
      IPAddress bufIP;
      IPAddressFromString(bufIP,valueString.c_str());
      deviceConfig->server_address_ip = bufIP;
      deviceConfig->server_address_length = '\0';
    }
    else if(server_address_type == '1'){
      gotSomething = true;
      valueString.toCharArray(deviceConfig->server_address_domain,valueString.length()+1);
      deviceConfig->server_address_domain[valueString.length()] = '\0';
      deviceConfig->server_address_domain[253] = '\0';
    }
    else
      return String("{\"r\":-1}");
    
    
  }

  valueStart = json.indexOf("\"server-public-key\":\"");
  if(valueStart>=0){
    valueEnd = json.indexOf('"',valueStart+21);
    valueString = json.substring(valueStart+21,valueEnd);
    if(valueString.length()>2046){
      return String("{\"r\":-1}");
    }
    gotSomething = true;
    const size_t len = (valueString.length()+1)/2;
    uint8_t buf[len];
    hex_decode(buf, len, valueString.c_str());
    memcpy(deviceConfig->server_public_key,buf,SERVER_PUBLIC_KEY_LENGTH);
    
    if(len>386){
      uint8_t domainLength;
      domainLength = buf[385];
      deviceConfig->server_address_type = buf[384];
      if(deviceConfig->server_address_type == IP_ADDRESS){
        uint8_t ipBuf[4];
        memcpy(ipBuf,buf+386,4);
        deviceConfig->server_address_ip = (ipBuf[3] << 24) | (ipBuf[2] << 16) | (ipBuf[1] << 8)  |  ipBuf[0];
        deviceConfig->server_address_length = '\0';
        
      }
      else if(deviceConfig->server_address_type == DOMAIN_NAME && domainLength < 254){
        memcpy(deviceConfig->server_address_domain,buf+386,domainLength);
        deviceConfig->server_address_domain[domainLength] = '\0';
        deviceConfig->server_address_domain[253] = '\0';
        deviceConfig->server_address_length = domainLength;
      }
      else{
        return String("{\"r\":-1}");
      }

    }
  }

  if(!gotSomething)
    return String("{\"r\":-1}");
  else{
    //write config
    writeDeviceConfig();
    return String("{\"r\":0}");
  }
}

String configure_ap_from_JSON(String json){

  int16_t valueStart = json.indexOf("\"ssid\":\"");
  if(valueStart<0)
    return String("{\"r\":-1}");

  int16_t valueEnd = json.indexOf('"',valueStart+8);
  if(valueEnd-valueStart < 1)
    return String("{\"r\":-1}");
  String ssid = json.substring(valueStart+8,valueEnd);
  ssid.trim();
  if(ssid.length()>64)
    return String("{\"r\":-1}");
  ssid.toCharArray(deviceConfig->ssid,ssid.length()+1);
  deviceConfig->ssid[ssid.length()] = '\0';

  valueStart = json.indexOf("\"ch\":");
  uint8_t ch = 0;
  if(valueStart>=0){
    valueEnd = json.indexOf(',',valueStart+5);
    ch = json.substring(valueStart+5,valueEnd).toInt();
  }
  deviceConfig->channel = ch;

  valueStart = json.indexOf("\"sec\":");
  uint8_t sec = false;
  if(valueStart>=0){
    valueEnd = json.indexOf(',',valueStart+6);
    if(json.substring(valueStart+6,valueEnd).equals(String("0")))
      sec = false;
    else
      sec = true;
  }

  char passcode[65];
  if(sec == true){
    valueStart = json.indexOf("\"pwd\":\"");
    if(valueStart<0)
      return String("{\"r\":-1}");

    valueEnd = json.indexOf('"',valueStart+7);
    if(valueEnd-(valueStart+7) != 256)
      return String("{\"r\":-1}");
    char encodedPasscode[257];
    String passcodeString = json.substring(valueStart+7,valueEnd);
    passcodeString.trim();
    passcodeString.toCharArray(encodedPasscode,257);
    int decodeLength = decrypt((char*)deviceConfig->passcode, 65, encodedPasscode);
    deviceConfig->passcode[decodeLength] = '\0';
  }
  else{
    deviceConfig->passcode[0] = '\0';
  }
  writeDeviceConfig();
  return String("{\"r\":0}");

  
}


String pub_key(){
  String response;
  const int length = 162;
  const uint8_t* data = deviceConfig->device_public_key;
  for (unsigned i=length; i-->0; ) {
    uint8_t v = *data++;
    response += ascii_nibble(v>>4);
    response += ascii_nibble(v&0xF);
  }
  return response;
}

bool provision_keys(bool force){//(bool force){
    if(deviceConfig->device_private_key[0] != 0x00 && deviceConfig->device_private_key[0] != 0xFF && !force){
        return true;
      }
  #ifdef DEBUG_SETUP
    Serial.println("Provision Keys");
  #endif
  if(generatePrivateKey(deviceConfig->device_private_key)){
    parse_device_pubkey_from_privkey(deviceConfig->device_public_key,deviceConfig->device_private_key);
    #ifdef DEBUG_SETUP
      const int length = 612;
      const uint8_t* data = deviceConfig->device_private_key;
      for (unsigned i=length; i-->0; ) {
        uint8_t v = *data++;
        Serial.write(ascii_nibble(v>>4));
        Serial.write(ascii_nibble(v&0xF));
      }
      Serial.write('\n');

    #endif
    writeDeviceConfig();
    return true;//generated
  }

  #ifdef DEBUG_SETUP
    Serial.println("Provision Keys FAILED");
  #endif
  
  return false; //not generate
}

void set_system_mode(System_Mode_TypeDef mode){
  if(system_mode == DEFAULT_MODE && mode == DEFAULT_MODE)
    system_mode = AUTOMATIC;
  else if(mode == DEFAULT_MODE)
    return;
  else
    system_mode = mode;
}
System_Mode_TypeDef get_system_mode(void){
  return system_mode;
}
void set_oakboot_defaults(uint8_t failure_rom){ //0 = update rom, 1 = config rom, 2 = user rom
  bool changed = false;

  if(failure_rom != bootConfig->rom_on_swdt){
    bootConfig->rom_on_swdt = failure_rom;
    changed = true;
  }
  if(failure_rom != bootConfig->rom_on_hwdt){
    bootConfig->rom_on_hwdt = failure_rom;
    changed = true; 
  }
  if(failure_rom != bootConfig->rom_on_exception){
    bootConfig->rom_on_exception = failure_rom;
    changed = true;
  }
  if(failure_rom != bootConfig->rom_on_gpio){
    bootConfig->rom_on_gpio = failure_rom; 
    changed = true;
  }
  if(failure_rom != bootConfig->rom_on_invalid){
    bootConfig->rom_on_invalid = failure_rom;
    changed = true;
  }
  if(failure_rom != bootConfig->rom_on_reinit){
    bootConfig->rom_on_reinit = failure_rom;
    changed = true;
  }
  if(1 != bootConfig->mode){ //allow gpio boot to config
    bootConfig->mode = 1;
    changed = true;
  }
  if(changed){
    writeBootConfig();
  }
}
void set_bootloader_reason_write_skip(void){
  if(bootConfig->reset_write_skip != 1){
    bootConfig->reset_write_skip = 1;
    writeBootConfig();
  }
}
void init_bootloader_flags(void){
  set_bootloader_reason_write_skip();
  set_oakboot_defaults(1);
}
uint8_t read_factory_reason(){
  return bootConfig->factory_reason;
}
void clear_factory_reason(){
  if(bootConfig->factory_reason != 'N')
  bootConfig->factory_reason = 'N';
  writeBootConfig();
}

}; // particle_core

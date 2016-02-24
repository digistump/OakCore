#ifndef particle_globals_h
#define particle_globals_h

//#define DEBUG_SETUP

//#define OAK_SYSTEM_ROM_4F616B 82


#define PRODUCT_ID 82
#define PLATFORM_ID 82
#define OAK_SYSTEM_VERSION_INTEGER 5
#define OAK_SYSTEM_VERSION_MAJOR 1
#define OAK_SYSTEM_VERSION_MINOR 0
#define OAK_SYSTEM_VERSION_RELEASE 2


typedef enum
{
  DEFAULT_MODE=0, AUTOMATIC = 1, SEMI_AUTOMATIC = 2, MANUAL = 3, SAFE_MODE=4
} System_Mode_TypeDef;
typedef enum
{
  PUBLIC = 0, PRIVATE = 1
} Spark_Event_TypeDef;

typedef enum
{
  MY_DEVICES,
  ALL_DEVICES
} Spark_Subscription_Scope_TypeDef;
#endif
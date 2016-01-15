/**
 ******************************************************************************
 * @file    OakParticle.h
 * @author  Satish Nair, Zachary Crockett, Matthew McGowan
 ******************************************************************************
  Copyright (c) 2013-2015 Particle Industries, Inc.  All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, either
  version 3 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, see <http://www.gnu.org/licenses/>.
  ******************************************************************************
 */

#ifndef OakParticle_h
#define OakParticle_h

#include <cstring>
#include "particle.h"

#ifdef SPARK_NO_CLOUD
#define CLOUD_FN(x,y) (y)
#else
#define CLOUD_FN(x,y) (x)
#endif


class CloudClass {
public:
    CloudClass();

    static inline bool variable(const char* varKey, const int& var)
    {
        return variable(varKey, &var, particle_core::INT);
    }
    static inline bool variable(const char* varKey, const uint32_t& var)
    {
        return variable(varKey, &var, particle_core::INT);
    }

    static inline bool variable(const char* varKey, const double& var)
    {
        return variable(varKey, &var, particle_core::DOUBLE);
    }

    static inline bool variable(const char* varKey, const String& var)
    {
        return variable(varKey, &var, particle_core::STRING);
    }

    static inline bool variable(const char* varKey, const char* var)
    {
        return variable(varKey, var, particle_core::STRING);
    }

    template<std::size_t N>
    static inline bool variable(const char* varKey, const char var[N])
    {
        return variable(varKey, var, particle_core::STRING);
    }

    template<std::size_t N>
    static inline bool variable(const char* varKey, const unsigned char var[N])
    {
        return variable(varKey, var, particle_core::STRING);
    }

    static inline bool variable(const char *varKey, const uint8_t* userVar, const particle_core::CloudVariableTypeString& userVarType)
    {
        return variable(varKey, (const char*)userVar, userVarType);
    }

    template<typename T> static bool variable(const char *varKey, const typename T::varref userVar, const T& userVarType);

    static bool variable(const char *varKey, const int32_t* userVar, const particle_core::CloudVariableTypeInt& userVarType);
    static bool variable(const char *varKey, const uint32_t* userVar, const particle_core::CloudVariableTypeInt& userVarType);

    // Return clear errors for common misuses of Particle.variable()
    template<typename T, std::size_t N>
    static inline bool variable(const char *varKey, const T (*userVar)[N], const particle_core::CloudVariableTypeString& userVarType)
    {
        static_assert(sizeof(T)==0, "\n\nUse Particle.variable(\"name\", myVar, STRING); without & in front of myVar\n\n");
        return false;
    }

    template<typename T>
    static bool variable(const T *varKey, const String *userVar, const particle_core::CloudVariableTypeString& userVarType);

    template<typename T>
    static inline bool variable(const T *varKey, const String &userVar, const particle_core::CloudVariableTypeString& userVarType)
    {
        static_assert(sizeof(T)==0, "\n\nIn Particle.variable(\"name\", myVar, STRING); myVar must be declared as char myVar[] not String myVar\n\n");
        return false;
    }

    static bool function(const char *funcKey, particle_core::user_function_int_str_t* func);
    static bool function(const char *funcKey, particle_core::user_std_function_int_str_t func, void* reserved=NULL);

    template <typename T>
    static void function(const char *funcKey, int (T::*func)(String), T *instance);

    bool publish(const char *eventName, particle_core::Spark_Event_TypeDef eventType=particle_core::PUBLIC);
    bool publish(const char *eventName, const char *eventData, particle_core::Spark_Event_TypeDef eventType=particle_core::PUBLIC);
    bool publish(const char *eventName, const char *eventData, int ttl, particle_core::Spark_Event_TypeDef eventType=particle_core::PUBLIC);

    bool subscribe(const char *eventName, EventHandler handler, particle_core::Spark_Subscription_Scope_TypeDef scope=particle_core::ALL_DEVICES);
    bool subscribe(const char *eventName, EventHandler handler, const char *deviceID);
    bool subscribe(const char *eventName, particle_core::wiring_event_handler_t handler, particle_core::Spark_Subscription_Scope_TypeDef scope=particle_core::ALL_DEVICES);
    bool subscribe(const char *eventName, particle_core::wiring_event_handler_t handler, const char *deviceID);

    template <typename T>
    bool subscribe(const char *eventName, void (T::*handler)(const char *, const char *), T *instance, particle_core::Spark_Subscription_Scope_TypeDef scope=particle_core::ALL_DEVICES);
    template <typename T>
    bool subscribe(const char *eventName, void (T::*handler)(const char *, const char *), T *instance, const char *deviceID);

    void unsubscribe();

    bool syncTime(void);
/*
    static void sleep(long seconds) __attribute__ ((deprecated("Please use System.sleep() instead.")))
    { SystemClass::sleep(seconds); }
    static void sleep(Spark_Sleep_TypeDef sleepMode, long seconds=0) __attribute__ ((deprecated("Please use System.sleep() instead.")))
    { SystemClass::sleep(sleepMode, seconds); }
    static void sleep(uint16_t wakeUpPin, InterruptMode edgeTriggerMode, long seconds=0) __attribute__ ((deprecated("Please use System.sleep() instead.")))
    { SystemClass::sleep(wakeUpPin, edgeTriggerMode, seconds); }
*/
    static void initialize(void);
    static bool connected(void);
    static bool disconnected(void);
    static bool connect(void);
    static void disconnect(void);
    static void process(void);
    static String deviceID(void);

private:

    //static bool register_function(cloud_function_t fn, void* data, const char* funcKey);
    //static int call_raw_user_function(void* data, const char* param, void* reserved);
    //static int call_std_user_function(void* data, const char* param, void* reserved);

    //static void call_wiring_event_handler(const void* param, const char *event_name, const char *data);

    bool subscribe_wiring(const char *eventName, particle_core::wiring_event_handler_t handler, particle_core::Spark_Subscription_Scope_TypeDef scope, const char *deviceID = NULL);

    static const void* update_string_variable(const char* name, particle_core::Spark_Data_TypeDef type, const void* var, void* reserved);
};

extern CloudClass Particle;

#endif // OakParticle_h

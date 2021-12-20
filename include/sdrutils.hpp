/*
// Copyright (c) 2018 Intel Corporation
// Copyright (c) 2021 Portwell Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "commandutils.hpp"
#include "types.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/bimap.hpp>
#include <boost/container/flat_map.hpp>
#include <ipmid/types.hpp>
#include <phosphor-logging/log.hpp>

#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#pragma once

namespace ipmi
{
namespace sensor 
{

extern const IdInfoMap sensors;

inline static uint16_t getSensorNumberFromPath(const std::string& path)
{
    uint16_t sensorNum = 0xFF;

    for (const auto &sensor : sensors) {
        if (sensor.second.sensorPath.compare(path) == 0) {
            sensorNum = static_cast<uint16_t>(sensor.first);
            break;
        }
    }
    return sensorNum;
}

inline static uint8_t getSensorEventTypeFromPath(const std::string& path)
{
    // TODO: Add support for additional reading types as needed
    return 0x1; // reading type = threshold
}

inline static uint8_t getSensorTypeFromPath(const std::string& path)
{
    uint8_t sensorType = 0;

    for (const auto &sensor : sensors) {
        if (sensor.second.sensorPath.compare(path) == 0) {
            sensorType = static_cast<uint8_t>(sensor.second.sensorType);
            break;
        }
    }
    return sensorType;
}

} // namespace sensor
} // namespace ipmi

struct CmpStr
{
    bool operator()(const char* a, const char* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

enum class SensorTypeCodes : uint8_t
{
    reserved = 0x0,
    temperature = 0x1,
    voltage = 0x2,
    current = 0x3,
    fan = 0x4,
    other = 0xB,
};

const static boost::container::flat_map<const char*, SensorTypeCodes, CmpStr>
    sensorTypes{{{"temperature", SensorTypeCodes::temperature},
                 {"voltage", SensorTypeCodes::voltage},
                 {"current", SensorTypeCodes::current},
                 {"fan_tach", SensorTypeCodes::fan},
                 {"fan_pwm", SensorTypeCodes::fan},
                 {"power", SensorTypeCodes::other}}};

inline static std::string getSensorTypeStringFromPath(const std::string& path)
{
    // get sensor type string from path, path is defined as
    // /xyz/openbmc_project/sensors/<type>/label
    size_t typeEnd = path.rfind("/");
    if (typeEnd == std::string::npos)
    {
        return path;
    }
    size_t typeStart = path.rfind("/", typeEnd - 1);
    if (typeStart == std::string::npos)
    {
        return path;
    }
    // Start at the character after the '/'
    typeStart++;
    return path.substr(typeStart, typeEnd - typeStart);
}

inline static uint8_t getSensorTypeFromPath(const std::string& path)
{
    uint8_t sensorType = 0;
    std::string type = getSensorTypeStringFromPath(path);
    auto findSensor = sensorTypes.find(type.c_str());
    if (findSensor != sensorTypes.end())
    {
        sensorType = static_cast<uint8_t>(findSensor->second);
    } // else default 0x0 RESERVED

    return sensorType;
}

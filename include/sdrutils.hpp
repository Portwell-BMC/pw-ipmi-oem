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

#ifdef USING_ENTITY_MANAGER_DECORATORS
struct CmpStr
{
    bool operator()(const char* a, const char* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

enum class SensorTypeCodes : uint8_t
{
    reserved = 0x00,
    temperature = 0x01,
    voltage = 0x02,
    current = 0x03,
    fan = 0x04,
    processor = 0x07,
    power_unit = 0x09,
    other = 0x0b,
    memory = 0x0c,
    buttons = 0x14,
    watchdog2 = 0x23,
};

enum class SensorEventTypeCodes : uint8_t
{
    unspecified = 0x00,
    threshold = 0x01,
    sensorSpecified = 0x6f
};

const static boost::container::flat_map<
    const char*, std::pair<SensorTypeCodes, SensorEventTypeCodes>, CmpStr>
    sensorTypes{
        {{"temperature", std::make_pair(SensorTypeCodes::temperature,
                                        SensorEventTypeCodes::threshold)},
         {"voltage", std::make_pair(SensorTypeCodes::voltage,
                                    SensorEventTypeCodes::threshold)},
         {"current", std::make_pair(SensorTypeCodes::current,
                                    SensorEventTypeCodes::threshold)},
         {"fan_tach", std::make_pair(SensorTypeCodes::fan,
                                     SensorEventTypeCodes::threshold)},
         {"fan_pwm", std::make_pair(SensorTypeCodes::fan,
                                    SensorEventTypeCodes::threshold)},
         {"processor", std::make_pair(SensorTypeCodes::processor,
                                      SensorEventTypeCodes::sensorSpecified)},
         {"power", std::make_pair(SensorTypeCodes::other,
                                  SensorEventTypeCodes::threshold)},
         {"memory", std::make_pair(SensorTypeCodes::memory,
                                   SensorEventTypeCodes::sensorSpecified)},
         {"state", std::make_pair(SensorTypeCodes::power_unit,
                                  SensorEventTypeCodes::sensorSpecified)},
         {"buttons", std::make_pair(SensorTypeCodes::buttons,
                                    SensorEventTypeCodes::sensorSpecified)},
         {"watchdog", std::make_pair(SensorTypeCodes::watchdog2,
                                     SensorEventTypeCodes::sensorSpecified)}}};

struct CmpStrVersion
{
    bool operator()(std::string a, std::string b) const
    {
        return strverscmp(a.c_str(), b.c_str()) < 0;
    }
};

using SensorSubTree = boost::container::flat_map<
    std::string,
    boost::container::flat_map<std::string, std::vector<std::string>>,
    CmpStrVersion>;

using SensorNumMap = boost::bimap<int, std::string>;

static constexpr size_t sensorTypeCodes = 0;
static constexpr size_t sensorEventTypeCodes = 1;

static constexpr uint16_t maxSensorsPerLUN = 255;
static constexpr uint16_t maxIPMISensors = (maxSensorsPerLUN * 3);
static constexpr uint16_t lun1Sensor0 = 0x100;
static constexpr uint16_t lun3Sensor0 = 0x300;
static constexpr uint16_t invalidSensorNumber = 0xFFFF;
static constexpr uint8_t reservedSensorNumber = 0xFF;

namespace details
{

// Enable/disable the logging of stats instrumentation
static constexpr bool enableInstrumentation = false;

class IPMIStatsEntry
{
  private:
    int numReadings = 0;
    int numMissings = 0;
    int numStreakRead = 0;
    int numStreakMiss = 0;
    double minValue = 0.0;
    double maxValue = 0.0;
    std::string sensorName;

  public:
    const std::string& getName(void) const
    {
        return sensorName;
    }

    void updateName(std::string_view name)
    {
        sensorName = name;
    }

    // Returns true if this is the first successful reading
    // This is so the caller can log the coefficients used
    bool updateReading(double reading, int raw)
    {
        if constexpr (!enableInstrumentation)
        {
            return false;
        }

        bool first = ((numReadings == 0) && (numMissings == 0));

        // Sensors can use "nan" to indicate unavailable reading
        if (!(std::isfinite(reading)))
        {
            // Only show this if beginning a new streak
            if (numStreakMiss == 0)
            {
                std::cerr << "IPMI sensor " << sensorName
                          << ": Missing reading, byte=" << raw
                          << ", Reading counts good=" << numReadings
                          << " miss=" << numMissings
                          << ", Prior good streak=" << numStreakRead << "\n";
            }

            numStreakRead = 0;
            ++numMissings;
            ++numStreakMiss;

            return first;
        }

        // Only show this if beginning a new streak and not the first time
        if ((numStreakRead == 0) && (numReadings != 0))
        {
            std::cerr << "IPMI sensor " << sensorName
                      << ": Recovered reading, value=" << reading
                      << " byte=" << raw
                      << ", Reading counts good=" << numReadings
                      << " miss=" << numMissings
                      << ", Prior miss streak=" << numStreakMiss << "\n";
        }

        // Initialize min/max if the first successful reading
        if (numReadings == 0)
        {
            std::cerr << "IPMI sensor " << sensorName
                      << ": First reading, value=" << reading << " byte=" << raw
                      << "\n";

            minValue = reading;
            maxValue = reading;
        }

        numStreakMiss = 0;
        ++numReadings;
        ++numStreakRead;

        // Only provide subsequent output if new min/max established
        if (reading < minValue)
        {
            std::cerr << "IPMI sensor " << sensorName
                      << ": Lowest reading, value=" << reading
                      << " byte=" << raw << "\n";

            minValue = reading;
        }

        if (reading > maxValue)
        {
            std::cerr << "IPMI sensor " << sensorName
                      << ": Highest reading, value=" << reading
                      << " byte=" << raw << "\n";

            maxValue = reading;
        }

        return first;
    }
};

class IPMIStatsTable
{
  private:
    std::vector<IPMIStatsEntry> entries;

  private:
    void padEntries(size_t index)
    {
        char hexbuf[16];

        // Pad vector until entries[index] becomes a valid index
        while (entries.size() <= index)
        {
            // As name not known yet, use human-readable hex as name
            IPMIStatsEntry newEntry;
            sprintf(hexbuf, "0x%02zX", entries.size());
            newEntry.updateName(hexbuf);

            entries.push_back(std::move(newEntry));
        }
    }

  public:
    void wipeTable(void)
    {
        entries.clear();
    }

    const std::string& getName(size_t index)
    {
        padEntries(index);
        return entries[index].getName();
    }

    void updateName(size_t index, std::string_view name)
    {
        padEntries(index);
        entries[index].updateName(name);
    }

    bool updateReading(size_t index, double reading, int raw)
    {
        padEntries(index);
        return entries[index].updateReading(reading, raw);
    }
};

// This object is global singleton, used from a variety of places
inline IPMIStatsTable sdrStatsTable;

inline static uint16_t getSensorSubtree(std::shared_ptr<SensorSubTree>& subtree)
{
    static std::shared_ptr<SensorSubTree> sensorTreePtr;
    static uint16_t sensorUpdatedIndex = 0;
    sd_bus* bus = NULL;
    int ret = sd_bus_default_system(&bus);
    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to connect to system bus",
            phosphor::logging::entry("ERRNO=0x%X", -ret));
        sd_bus_unref(bus);
        return sensorUpdatedIndex;
    }
    sdbusplus::bus::bus dbus(bus);
    static sdbusplus::bus::match::match sensorAdded(
        dbus,
        "type='signal',member='InterfacesAdded',arg0path='/xyz/openbmc_project/"
        "sensors/'",
        [](sdbusplus::message::message& m) { sensorTreePtr.reset(); });

    static sdbusplus::bus::match::match sensorRemoved(
        dbus,
        "type='signal',member='InterfacesRemoved',arg0path='/xyz/"
        "openbmc_project/sensors/'",
        [](sdbusplus::message::message& m) { sensorTreePtr.reset(); });

    if (sensorTreePtr)
    {
        subtree = sensorTreePtr;
        return sensorUpdatedIndex;
    }

    sensorTreePtr = std::make_shared<SensorSubTree>();

    auto mapperCall =
        dbus.new_method_call("xyz.openbmc_project.ObjectMapper",
                             "/xyz/openbmc_project/object_mapper",
                             "xyz.openbmc_project.ObjectMapper", "GetSubTree");
    static constexpr const auto depth = 2;
    static constexpr std::array<const char*, 3> interfaces = {
        "xyz.openbmc_project.Sensor.Value",
        "xyz.openbmc_project.Sensor.Threshold.Warning",
        "xyz.openbmc_project.Sensor.Threshold.Critical"};
    mapperCall.append("/xyz/openbmc_project/sensors", depth, interfaces);

    try
    {
        auto mapperReply = dbus.call(mapperCall);
        mapperReply.read(*sensorTreePtr);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return sensorUpdatedIndex;
    }
    subtree = sensorTreePtr;
    sensorUpdatedIndex++;
    // The SDR is being regenerated, wipe the old stats
    sdrStatsTable.wipeTable();
    return sensorUpdatedIndex;
}

inline static bool getSensorNumMap(std::shared_ptr<SensorNumMap>& sensorNumMap)
{
    static std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    bool sensorNumMapUpated = false;
    static uint16_t prevSensorUpdatedIndex = 0;
    std::shared_ptr<SensorSubTree> sensorTree;
    uint16_t curSensorUpdatedIndex = details::getSensorSubtree(sensorTree);
    if (!sensorTree)
    {
        return sensorNumMapUpated;
    }

    if ((curSensorUpdatedIndex == prevSensorUpdatedIndex) && sensorNumMapPtr)
    {
        sensorNumMap = sensorNumMapPtr;
        return sensorNumMapUpated;
    }
    prevSensorUpdatedIndex = curSensorUpdatedIndex;

    sensorNumMapPtr = std::make_shared<SensorNumMap>();

    uint16_t sensorNum = 0;
    uint16_t sensorIndex = 0;
    for (const auto& sensor : *sensorTree)
    {
        sensorNumMapPtr->insert(
            SensorNumMap::value_type(sensorNum, sensor.first));
        sensorIndex++;
        if (sensorIndex == maxSensorsPerLUN)
        {
            sensorIndex = lun1Sensor0;
        }
        else if (sensorIndex == (lun1Sensor0 | maxSensorsPerLUN))
        {
            // Skip assigning LUN 0x2 any sensors
            sensorIndex = lun3Sensor0;
        }
        else if (sensorIndex == (lun3Sensor0 | maxSensorsPerLUN))
        {
            // this is an error, too many IPMI sensors
            throw std::out_of_range("Maximum number of IPMI sensors exceeded.");
        }
        sensorNum = sensorIndex;
    }
    sensorNumMap = sensorNumMapPtr;
    sensorNumMapUpated = true;
    return sensorNumMapUpated;
}
} // namespace details

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
        sensorType =
            static_cast<uint8_t>(std::get<sensorTypeCodes>(findSensor->second));
    } // else default 0x0 RESERVED

    return sensorType;
}

inline static uint16_t getSensorNumberFromPath(const std::string& path)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        return invalidSensorNumber;
    }

    try
    {
        return sensorNumMapPtr->right.at(path);
    }
    catch (const std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return invalidSensorNumber;
    }
}

inline static uint8_t getSensorEventTypeFromPath(const std::string& path)
{
    uint8_t sensorEventType = 0;
    std::string type = getSensorTypeStringFromPath(path);
    auto findSensor = sensorTypes.find(type.c_str());
    if (findSensor != sensorTypes.end())
    {
        sensorEventType = static_cast<uint8_t>(
            std::get<sensorEventTypeCodes>(findSensor->second));
    }

    return sensorEventType;
}

inline static std::string getPathFromSensorNumber(uint16_t sensorNum)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        return std::string();
    }

    try
    {
        return sensorNumMapPtr->left.at(sensorNum);
    }
    catch (const std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return std::string();
    }
}

#else

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

#endif //USING_ENTITY_MANAGER_DECORATORS

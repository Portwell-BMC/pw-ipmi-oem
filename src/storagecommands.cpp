/*
// Copyright (c) 2017-2019 Intel Corporation
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

#include "storagecommands.hpp"

#include "commandutils.hpp"
#include "ipmi_to_redfish_hooks.hpp"
#include "sdrutils.hpp"
#include "types.hpp"

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/process.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-ipmi-host/selutility.hpp>
#include <phosphor-ipmi-host/sensorhandler.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>

#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string_view>

using namespace phosphor::logging;

static constexpr bool DEBUG = false;

namespace pw_oem::ipmi::sel
{
static const std::filesystem::path selLogDir = SEL_LOG_DIR;
static const std::string selLogFilename = "ipmi_sel";

static int getFileTimestamp(const std::filesystem::path& file)
{
    struct stat st;

    if (stat(file.c_str(), &st) >= 0)
    {
        return st.st_mtime;
    }
    return ::ipmi::sel::invalidTimeStamp;
}

namespace erase_time
{
static constexpr const char* selEraseTimestamp = "/var/lib/ipmi/sel_erase_time";

void save()
{
    // open the file, creating it if necessary
    int fd = open(selEraseTimestamp, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        std::cerr << "Failed to open file\n";
        return;
    }

    // update the file timestamp to the current time
    if (futimens(fd, NULL) < 0)
    {
        std::cerr << "Failed to update timestamp: "
                  << std::string(strerror(errno));
    }
    close(fd);
}

int get()
{
    return getFileTimestamp(selEraseTimestamp);
}
} // namespace erase_time
} // namespace pw_oem::ipmi::sel

namespace ipmi
{

namespace storage
{
const static constexpr char* bmcTimeService =
    "xyz.openbmc_project.Time.Manager";
const static constexpr char* bmcTimeObject =
    "/xyz/openbmc_project/time/bmc";
static constexpr const char* bmcTimeIntf = 
    "xyz.openbmc_project.Time.EpochTime";
const static constexpr char* bmcTimeProp = "Elapsed";

static ipmi::ServiceCache BmcTimeService(bmcTimeIntf, bmcTimeObject);

void registerStorageFunctions() __attribute__((constructor));

static bool getSELLogFiles(std::vector<std::filesystem::path>& selLogFiles)
{
    // Loop through the directory looking for ipmi_sel log files
    for (const std::filesystem::directory_entry& dirEnt :
         std::filesystem::directory_iterator(pw_oem::ipmi::sel::selLogDir))
    {
        std::string filename = dirEnt.path().filename();
        if (boost::starts_with(filename, pw_oem::ipmi::sel::selLogFilename))
        {
            // If we find an ipmi_sel log file, save the path
            selLogFiles.emplace_back(pw_oem::ipmi::sel::selLogDir /
                                     filename);
        }
    }
    // As the log files rotate, they are appended with a ".#" that is higher for
    // the older logs. Since we don't expect more than 10 log files, we
    // can just sort the list to get them in order from newest to oldest
    std::sort(selLogFiles.begin(), selLogFiles.end());

    return !selLogFiles.empty();
}

static int countSELEntries()
{
    // Get the list of ipmi_sel log files
    std::vector<std::filesystem::path> selLogFiles;
    if (!getSELLogFiles(selLogFiles))
    {
        return 0;
    }
    int numSELEntries = 0;
    // Loop through each log file and count the number of logs
    for (const std::filesystem::path& file : selLogFiles)
    {
        std::ifstream logStream(file);
        if (!logStream.is_open())
        {
            continue;
        }

        std::string line;
        while (std::getline(logStream, line))
        {
            numSELEntries++;
        }
    }
    return numSELEntries;
}

static bool findSELEntry(const int recordID,
                         const std::vector<std::filesystem::path>& selLogFiles,
                         std::string& entry)
{
    // Record ID is the first entry field following the timestamp. It is
    // preceded by a space and followed by a comma
    std::string search = " " + std::to_string(recordID) + ",";

    // Loop through the ipmi_sel log entries
    for (const std::filesystem::path& file : selLogFiles)
    {
        std::ifstream logStream(file);
        if (!logStream.is_open())
        {
            continue;
        }

        while (std::getline(logStream, entry))
        {
            // Check if the record ID matches
            if (entry.find(search) != std::string::npos)
            {
                return true;
            }
        }
    }
    return false;
}

static uint16_t
    getNextRecordID(const uint16_t recordID,
                    const std::vector<std::filesystem::path>& selLogFiles)
{
    uint16_t nextRecordID = recordID + 1;
    std::string entry;
    if (findSELEntry(nextRecordID, selLogFiles, entry))
    {
        return nextRecordID;
    }
    else
    {
        return ipmi::sel::lastEntry;
    }
}

static int fromHexStr(const std::string& hexStr, std::vector<uint8_t>& data)
{
    for (unsigned int i = 0; i < hexStr.size(); i += 2)
    {
        try
        {
            data.push_back(static_cast<uint8_t>(
                std::stoul(hexStr.substr(i, 2), nullptr, 16)));
        }
        catch (const std::invalid_argument& e)
        {
            log<level::ERR>(e.what());
            return -1;
        }
        catch (const std::out_of_range& e)
        {
            log<level::ERR>(e.what());
            return -1;
        }
    }
    return 0;
}

ipmi::RspType<uint8_t,  // SEL version
              uint16_t, // SEL entry count
              uint16_t, // free space
              uint32_t, // last add timestamp
              uint32_t, // last erase timestamp
              uint8_t>  // operation support
    ipmiStorageGetSELInfo()
{
    constexpr uint8_t selVersion = ipmi::sel::selVersion;
    uint16_t entries = countSELEntries();
    uint32_t addTimeStamp = pw_oem::ipmi::sel::getFileTimestamp(
        pw_oem::ipmi::sel::selLogDir / pw_oem::ipmi::sel::selLogFilename);
    uint32_t eraseTimeStamp = pw_oem::ipmi::sel::erase_time::get();
    constexpr uint8_t operationSupport =
        pw_oem::ipmi::sel::selOperationSupport;
    constexpr uint16_t freeSpace =
        0xffff; // Spec indicates that more than 64kB is free

    return ipmi::responseSuccess(selVersion, entries, freeSpace, addTimeStamp,
                                 eraseTimeStamp, operationSupport);
}

using systemEventType = std::tuple<
    uint32_t, // Timestamp
    uint16_t, // Generator ID
    uint8_t,  // EvM Rev
    uint8_t,  // Sensor Type
    uint8_t,  // Sensor Number
    uint7_t,  // Event Type
    bool,     // Event Direction
    std::array<uint8_t, pw_oem::ipmi::sel::systemEventSize>>; // Event Data
using oemTsEventType = std::tuple<
    uint32_t,                                                   // Timestamp
    std::array<uint8_t, pw_oem::ipmi::sel::oemTsEventSize>>; // Event Data
using oemEventType =
    std::array<uint8_t, pw_oem::ipmi::sel::oemEventSize>; // Event Data

ipmi::RspType<uint16_t, // Next Record ID
              uint16_t, // Record ID
              uint8_t,  // Record Type
              std::variant<systemEventType, oemTsEventType,
                           oemEventType>> // Record Content
    ipmiStorageGetSELEntry(uint16_t reservationID, uint16_t targetID,
                           uint8_t offset, uint8_t size)
{
    // Only support getting the entire SEL record. If a partial size or non-zero
    // offset is requested, return an error
    if (offset != 0 || size != ipmi::sel::entireRecord)
    {
        return ipmi::responseRetBytesUnavailable();
    }

    // Check the reservation ID if one is provided or required (only if the
    // offset is non-zero)
    if (reservationID != 0 || offset != 0)
    {
        if (!checkSELReservation(reservationID))
        {
            return ipmi::responseInvalidReservationId();
        }
    }

    // Get the ipmi_sel log files
    std::vector<std::filesystem::path> selLogFiles;
    if (!getSELLogFiles(selLogFiles))
    {
        return ipmi::responseSensorInvalid();
    }

    std::string targetEntry;

    if (targetID == ipmi::sel::firstEntry)
    {
        // The first entry will be at the top of the oldest log file
        std::ifstream logStream(selLogFiles.back());
        if (!logStream.is_open())
        {
            return ipmi::responseUnspecifiedError();
        }

        if (!std::getline(logStream, targetEntry))
        {
            return ipmi::responseUnspecifiedError();
        }
    }
    else if (targetID == ipmi::sel::lastEntry)
    {
        // The last entry will be at the bottom of the newest log file
        std::ifstream logStream(selLogFiles.front());
        if (!logStream.is_open())
        {
            return ipmi::responseUnspecifiedError();
        }

        std::string line;
        while (std::getline(logStream, line))
        {
            targetEntry = line;
        }
    }
    else
    {
        if (!findSELEntry(targetID, selLogFiles, targetEntry))
        {
            return ipmi::responseSensorInvalid();
        }
    }

    // The format of the ipmi_sel message is "<Timestamp>
    // <ID>,<Type>,<EventData>,[<Generator ID>,<Path>,<Direction>]".
    // First get the Timestamp
    size_t space = targetEntry.find_first_of(" ");
    if (space == std::string::npos)
    {
        return ipmi::responseUnspecifiedError();
    }
    std::string entryTimestamp = targetEntry.substr(0, space);
    // Then get the log contents
    size_t entryStart = targetEntry.find_first_not_of(" ", space);
    if (entryStart == std::string::npos)
    {
        return ipmi::responseUnspecifiedError();
    }
    std::string_view entry(targetEntry);
    entry.remove_prefix(entryStart);
    // Use split to separate the entry into its fields
    std::vector<std::string> targetEntryFields;
    boost::split(targetEntryFields, entry, boost::is_any_of(","),
                 boost::token_compress_on);
    if (targetEntryFields.size() < 3)
    {
        return ipmi::responseUnspecifiedError();
    }
    std::string& recordIDStr = targetEntryFields[0];
    std::string& recordTypeStr = targetEntryFields[1];
    std::string& eventDataStr = targetEntryFields[2];

    uint16_t recordID;
    uint8_t recordType;
    try
    {
        recordID = std::stoul(recordIDStr);
        recordType = std::stoul(recordTypeStr, nullptr, 16);
    }
    catch (const std::invalid_argument&)
    {
        return ipmi::responseUnspecifiedError();
    }
    uint16_t nextRecordID = getNextRecordID(recordID, selLogFiles);
    std::vector<uint8_t> eventDataBytes;
    if (fromHexStr(eventDataStr, eventDataBytes) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    if (recordType == pw_oem::ipmi::sel::systemEvent)
    {
        // Get the timestamp
        std::tm timeStruct = {};
        std::istringstream entryStream(entryTimestamp);

        uint32_t timestamp = ipmi::sel::invalidTimeStamp;
        if (entryStream >> std::get_time(&timeStruct, "%Y-%m-%dT%H:%M:%S"))
        {
            timestamp = std::mktime(&timeStruct);
        }

        // Set the event message revision
        uint8_t evmRev = pw_oem::ipmi::sel::eventMsgRev;

        uint16_t generatorID = 0;
        uint8_t sensorType = 0;
        uint16_t sensorAndLun = 0;
        uint8_t sensorNum = 0xFF;
        uint7_t eventType = 0;
        bool eventDir = 0;
        std::array<uint8_t, pw_oem::ipmi::sel::systemEventSize> eventData{};
        // System SEL
        if (targetEntryFields.size() >= 6)
        {
            std::string& generatorIDStr = targetEntryFields[3];
            std::string& sensorPath = targetEntryFields[4];
            std::string& eventDirStr = targetEntryFields[5];
            const std::string bmcPathPrefix = "/xyz";
            const std::string platformEventPathPrefix = "PE_";
            const std::string addSELPathPrefix = "AddSEL_";

            // Get the generator ID
            try
            {
                generatorID = std::stoul(generatorIDStr, nullptr, 16);
            }
            catch (const std::invalid_argument&)
            {
                std::cerr << "Invalid Generator ID\n";
            }

            if (sensorPath.compare(0, bmcPathPrefix.size(), bmcPathPrefix) == 0)
            {
                // Get the sensor type, sensor number, and event type for the sensor
#ifdef USING_ENTITY_MANAGER_DECORATORS
                sensorType = getSensorTypeFromPath(sensorPath);
                sensorAndLun = getSensorNumberFromPath(sensorPath);
                sensorNum = static_cast<uint8_t>(sensorAndLun);
                eventType = getSensorEventTypeFromPath(sensorPath);
                if ((generatorID & 0x0001) == 0)
                {
                    // IPMB Address
                    generatorID |= sensorAndLun & 0x0300;
                }
                else
                {
                    // system software
                    generatorID |= sensorAndLun >> 8;
                }
#else
                sensorType = ipmi::sensor::getSensorTypeFromPath(sensorPath);
                sensorNum = ipmi::sensor::getSensorNumberFromPath(sensorPath);
                eventType = ipmi::sensor::getSensorEventTypeFromPath(sensorPath);
#endif
                std::copy_n(eventDataBytes.begin(),
                            std::min(eventDataBytes.size(), eventData.size()),
                            eventData.begin());
            }
            else if (sensorPath.compare(0, platformEventPathPrefix.size(), platformEventPathPrefix) == 0 ||
                     sensorPath.compare(0, addSELPathPrefix.size(), addSELPathPrefix) == 0)
            {
                if (eventDataBytes.size() == 8)
                {
                    sensorType = eventDataBytes[2];
                    sensorNum = eventDataBytes[3];
                    eventType = eventDataBytes[4] & 0x7F;
                    std::copy_n(eventDataBytes.begin() + 5, 3,
                                eventData.begin());
                }
                else if (eventDataBytes.size() == 7)
                {
                    sensorType = eventDataBytes[1];
                    sensorNum = eventDataBytes[2];
                    eventType = eventDataBytes[3] & 0x7F;
                    std::copy_n(eventDataBytes.begin() + 4, 3,
                                eventData.begin());
                }
            }
            else
            {
                std::cerr << "Unknown sensor path: " << sensorPath << "\n";
            }

            // Get the event direction
            try
            {
                eventDir = std::stoul(eventDirStr) ? 0 : 1;
            }
            catch (const std::invalid_argument&)
            {
                std::cerr << "Invalid Event Direction\n";
            }

            return ipmi::responseSuccess(
                nextRecordID, recordID, recordType,
                systemEventType{timestamp, generatorID, evmRev, sensorType,
                                sensorNum, eventType, eventDir, eventData});
        }
        else
        {
            std::cerr << "Invalid SEL entry\n";

            return ipmi::responseSuccess(
                nextRecordID, recordID, recordType,
                systemEventType{timestamp, generatorID, evmRev, sensorType,
                                sensorNum, eventType, eventDir, eventData});
        }
    }
    else if (recordType >= pw_oem::ipmi::sel::oemTsEventFirst &&
             recordType <= pw_oem::ipmi::sel::oemTsEventLast)
    {
        // Get the timestamp
        std::tm timeStruct = {};
        std::istringstream entryStream(entryTimestamp);

        uint32_t timestamp = ipmi::sel::invalidTimeStamp;
        if (entryStream >> std::get_time(&timeStruct, "%Y-%m-%dT%H:%M:%S"))
        {
            timestamp = std::mktime(&timeStruct);
        }

        // Only keep the bytes that fit in the record
        std::array<uint8_t, pw_oem::ipmi::sel::oemTsEventSize> eventData{};
        std::copy_n(eventDataBytes.begin(),
                    std::min(eventDataBytes.size(), eventData.size()),
                    eventData.begin());

        return ipmi::responseSuccess(nextRecordID, recordID, recordType,
                                     oemTsEventType{timestamp, eventData});
    }
    else if (recordType >= pw_oem::ipmi::sel::oemEventFirst)
    {
        // Only keep the bytes that fit in the record
        std::array<uint8_t, pw_oem::ipmi::sel::oemEventSize> eventData{};
        std::copy_n(eventDataBytes.begin(),
                    std::min(eventDataBytes.size(), eventData.size()),
                    eventData.begin());

        return ipmi::responseSuccess(nextRecordID, recordID, recordType,
                                     eventData);
    }

    return ipmi::responseUnspecifiedError();
}

ipmi::RspType<uint16_t> ipmiStorageAddSELEntry(
    ipmi::Context::ptr ctx,
    uint16_t recordID, uint8_t recordType,
    std::array<uint8_t, 13> selData)
{
    uint32_t timestamp = selData[0] | (selData[1] << 8) | 
                        (selData[2] << 16) | (selData[3] << 24);
    uint16_t generatorID = selData[4] | (selData[5] << 8);
    uint8_t evmRev = selData[6];
    uint8_t sensorType = selData[7];
    uint8_t sensorNum = selData[8];
    uint8_t eventType = selData[9];
    uint8_t eventData1 = selData[10];
    uint8_t eventData2 = selData[11];
    uint8_t eventData3 = selData[12];
    bool assert = true;
    std::string sensorPath;
    ipmi::ChannelInfo chInfo;

    if (ipmi::getChannelInfo(ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        log<level::ERR>("Failed to get Channel Info",
                        entry("CHANNEL=%d", ctx->channel));
        return ipmi::responseUnspecifiedError();
    }

    // Check for valid evmRev and Sensor Type(per Table 42 of spec)
#if 0
    // Some hosts do not set evmRev to 0x04
    if (evmRev != 0x04)
    {
        return ipmi::responseInvalidFieldRequest();
    }
#endif
    if ((sensorType > 0x2C) && (sensorType < 0xC0))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Per the IPMI spec, need to cancel any reservation when a SEL entry is
    // added
    cancelSELReservation();

    if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
        ipmi::EChannelMediumType::systemInterface)
    {
        sensorPath = "AddSEL_System";
    }
    else if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
             ipmi::EChannelMediumType::oem)
    {
        sensorPath = "AddSEL_Self";
    }
    else if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
             ipmi::EChannelMediumType::ipmb)
    {
        sensorPath = "AddSEL_Ipmb";
    }
    else
    {
        sensorPath = "AddSEL_Unknown";
    }

    assert = eventType & directionMask ? false : true;

    auto bus = getSdBus();
    std::string service =
        ipmi::getService(*bus, ipmiSELAddInterface, ipmiSELPath);
    sdbusplus::message::message writeSEL;
    if (recordType == pw_oem::ipmi::sel::systemEvent)
    {
        std::vector<uint8_t> eventData{selData.begin() + 6, selData.end()};
        writeSEL = bus->new_method_call(
            service.c_str(), ipmiSELPath, ipmiSELAddInterface, "IpmiSelAdd");
        writeSEL.append(ipmiSELAddMessage, sensorPath, eventData, assert,
                        generatorID);
    }
    else if (recordType >= pw_oem::ipmi::sel::oemTsEventFirst &&
             recordType <= pw_oem::ipmi::sel::oemTsEventLast)
    {
        std::vector<uint8_t> eventData{selData.begin() + 4, selData.end()};
        writeSEL = bus->new_method_call(
            service.c_str(), ipmiSELPath, ipmiSELAddInterface, "IpmiSelAddOem");
        writeSEL.append(ipmiSELAddMessage, eventData, recordType);
    }
    else if (recordType >= pw_oem::ipmi::sel::oemEventFirst)
    {
        std::vector<uint8_t> eventData{selData.begin(), selData.end()};
        writeSEL = bus->new_method_call(
            service.c_str(), ipmiSELPath, ipmiSELAddInterface, "IpmiSelAddOem");
        writeSEL.append(ipmiSELAddMessage, eventData, recordType);
    }
    else
    {
        return ipmi::responseUnspecifiedError();
    }
    try
    {
        bus->call(writeSEL);
    }
    catch (const sdbusplus::exception_t& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    unsigned int savedRecordID = 0xFFFF;
    auto getRecordId = bus->new_method_call(
        service.c_str(), ipmiSELPath, ipmiSELAddInterface, "GetCurrentRecordId");
    try
    {
        auto result = bus->call(getRecordId);
        result.read(savedRecordID);
        if (savedRecordID == 0 || savedRecordID > 0xFFFF)
        {
            savedRecordID = 0xFFFF;
            log<level::WARNING>("Invalid record ID",
                                entry("RecordID=%u", savedRecordID));
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    // Send this request to the Redfish hooks to log it as a Redfish message
    pw_oem::ipmi::sel::checkRedfishHooks(
        recordID, recordType, timestamp, generatorID, evmRev, sensorType,
        sensorNum, eventType, eventData1, eventData2, eventData3);

    return ipmi::responseSuccess(static_cast<uint16_t>(savedRecordID));
}

ipmi::RspType<uint8_t> ipmiStorageClearSEL(ipmi::Context::ptr ctx,
                                           uint16_t reservationID,
                                           const std::array<uint8_t, 3>& clr,
                                           uint8_t eraseOperation)
{
    if (!checkSELReservation(reservationID))
    {
        return ipmi::responseInvalidReservationId();
    }

    static constexpr std::array<uint8_t, 3> clrExpected = {'C', 'L', 'R'};
    if (clr != clrExpected)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Erasure status cannot be fetched, so always return erasure status as
    // `erase completed`.
    if (eraseOperation == ipmi::sel::getEraseStatus)
    {
        return ipmi::responseSuccess(ipmi::sel::eraseComplete);
    }

    // Check that initiate erase is correct
    if (eraseOperation != ipmi::sel::initiateErase)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Per the IPMI spec, need to cancel any reservation when the SEL is
    // cleared
    cancelSELReservation();

    // Save the erase time
    pw_oem::ipmi::sel::erase_time::save();

    // Clear the SEL by phosphor-sel-logger
    auto bus = getSdBus();
    std::string service =
        ipmi::getService(*bus, ipmiSELAddInterface, ipmiSELPath);
    auto clearSEL = bus->new_method_call(
        service.c_str(), ipmiSELPath, ipmiSELAddInterface, "Clear");
    try
    {
        bus->call(clearSEL);
    }
    catch (const sdbusplus::exception_t& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(ipmi::sel::eraseComplete);
}

ipmi::RspType<uint32_t> ipmiStorageGetSELTime()
{
    struct timespec selTime = {};

    if (clock_gettime(CLOCK_REALTIME, &selTime) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(selTime.tv_sec);
}

ipmi::RspType<> ipmiStorageSetSELTime(uint32_t selTime)
{
    auto bus = getSdBus();
    try
    {
        std::string service = BmcTimeService.getService(*bus);
        setDbusProperty(*bus, service, bmcTimeObject, bmcTimeIntf, bmcTimeProp,
                        static_cast<uint64_t>(selTime) * 1000000);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to set time",
                        entry("EXCEPTION=%s", e.what()),
                        entry("TIME=%u", selTime));
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

void registerStorageFunctions()
{
    // <Get SEL Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelInfo, ipmi::Privilege::User,
                          ipmiStorageGetSELInfo);

    // <Get SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelEntry, ipmi::Privilege::User,
                          ipmiStorageGetSELEntry);

    // <Add SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdAddSelEntry,
                          ipmi::Privilege::Operator, ipmiStorageAddSELEntry);

    // <Clear SEL>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdClearSel, ipmi::Privilege::Operator,
                          ipmiStorageClearSEL);

    // <Set SEL Time>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdSetSelTime,
                          ipmi::Privilege::Operator, ipmiStorageSetSELTime);
#if 0
    // <Get SEL Time>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelTime, ipmi::Privilege::User,
                          ipmiStorageGetSELTime);
#endif
}
} // namespace storage
} // namespace ipmi

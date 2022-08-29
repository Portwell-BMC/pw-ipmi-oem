/*
// Copyright (c) 2019 Intel Corporation
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

#include <boost/beast/core/span.hpp>
#include <ipmi_to_redfish_hooks.hpp>
#include <me_to_redfish_hooks.hpp>
#include <storagecommands.hpp>

#include <iomanip>
#include <sstream>
#include <string_view>

using namespace phosphor::logging;

namespace pw_oem::ipmi::sel
{

namespace redfish_hooks
{
static void toHexStr(const boost::beast::span<uint8_t> bytes,
                     std::string& hexStr)
{
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (const uint8_t& byte : bytes)
    {
        stream << std::setw(2) << static_cast<int>(byte);
    }
    hexStr = stream.str();
}

static std::string toHexStr(uint8_t byte)
{
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    stream << std::setw(2) << static_cast<int>(byte);
    return stream.str();
}

namespace bios_progress
{
static const boost::container::flat_map<uint8_t, std::string>
    postError = {
        {0x00, "Unspecified"},
        {0x01, "No system memory is physically installed in the system"},
        {0x02, "No usable system memory, "
               "all installed memory has experienced an unrecoverable failure"},
        {0x03, "Unrecoverable hard-disk/ATAPI/IDE failure"},
        {0x04, "Unrecoverable system-board failure"},
        {0x05, "Unrecoverable diskete subsystem failure"},
        {0x06, "Unrecoverable hard-disk controller failure"},
        {0x07, "Unrecoverable PS/2 or USB keyboard failure"},
        {0x08, "Removable boot media not found"},
        {0x09, "Unrecoverable video controller failure"},
        {0x0A, "No video device detected"},
        {0x0B, "BIOS ROM corruption detected"},
        {0x0C, "CPU voltage mismatch"},
        {0x0D, "CPU speed matching failure"}};

static const boost::container::flat_map<uint8_t, std::string>
    firmwareProgress = {
        {0x00, "Unspecified"},
        {0x01, "Memory initialization"},
        {0x02, "Hard-disk initialization"},
        {0x03, "Secondary processor(s) initialization"},
        {0x04, "User authentication"},
        {0x05, "User-initiated system setup"},
        {0x06, "USB resource configuration"},
        {0x07, "PCI resource configuration"},
        {0x08, "Option ROM initialization"},
        {0x09, "Video initialization"},
        {0x0A, "Cache initialization"},
        {0x0B, "SM Bus initialization"},
        {0x0C, "Keyboard controller initialization"},
        {0x0D, "Embedded controller/management controller initialization"},
        {0x0E, "Docking station attachment"},
        {0x0F, "Enabling docking station"},
        {0x10, "Docking station ejection"},
        {0x11, "Disable docking station"},
        {0x12, "Calling operating system wake-up vector"},
        {0x13, "Starting operating system boot process, e.g. calling Int 19h"},
        {0x14, "Baseboard or motherboard initialization"},
        {0x15, "reserved"},
        {0x16, "Floppy initialization"},
        {0x17, "Keyboard test"},
        {0x18, "Pointing device test"},
        {0x19, "Primary processor initialization"}};
} // namespace bios_progress

// Record a BIOS message as a Redfish message instead of a SEL record
static bool biosMessageHook(const SELData& selData, const std::string& ipmiRaw)
{
    // This is a BIOS message, so record it as a Redfish message instead
    // of a SEL record

    // Walk through the SEL request record to build the appropriate Redfish
    // message
    static constexpr std::string_view openBMCMessageRegistryVersion = "0.1";
    std::string messageID =
        "OpenBMC." + std::string(openBMCMessageRegistryVersion);
    std::vector<std::string> messageArgs;
    BIOSSensorType sensorType = static_cast<BIOSSensorType>(selData.sensorType);
    BIOSEventTypes eventType = static_cast<BIOSEventTypes>(selData.eventType);
    
    printf("biosMessageHook: sensorType=0x%02X, eventType=0x%02X\n", sensorType, eventType);
    printf("biosMessageHook: selData.offset=0x%02X\n", selData.offset);
    fflush(stdout);
    
    if (eventType != BIOSEventTypes::sensorSpecificDiscrete)
    {
        return defaultMessageHook(ipmiRaw);
    }

    switch (sensorType)
    {
        case BIOSSensorType::systemFirmwareProgress:
        {
            switch (selData.offset)
            {
                case 0x00:
                {
                    messageID += ".BIOSPOSTError";

                    const auto it = bios_progress::postError.find(selData.eventData2);
                    if (it == bios_progress::postError.end())
                    {
                        messageArgs.push_back("reserved");
                    }
                    else
                    {
                        messageArgs.push_back(it->second);
                    }
                    break;
                }
                case 0x01:
                {
                    messageID += ".BIOSHang";

                    const auto it = bios_progress::postError.find(selData.eventData2);
                    if (it == bios_progress::postError.end())
                    {
                        messageArgs.push_back("reserved");
                    }
                    else
                    {
                        messageArgs.push_back(it->second);
                    }
                    break;
                }
                case 0x02:
                {
                    messageID += ".BIOSProgress";

                    const auto it = bios_progress::firmwareProgress.find(selData.eventData2);
                    if (it == bios_progress::firmwareProgress.end())
                    {
                        messageArgs.push_back("reserved");
                    }
                    else
                    {
                        messageArgs.push_back(it->second);
                    }
                    break;
                }
                default:
                    return defaultMessageHook(ipmiRaw);
                    break;
            }
            break;
        }
        case BIOSSensorType::systemEvent:
        {
            switch (selData.offset)
            {
                case 0x00:
                    messageID += ".SystemReconfigured";
                    break;
                case 0x01:
                    messageID += ".OEMSystemBootEvent";
                    break;
                case 0x02:
                {
                    messageID += ".SystemHardwareFailure";
                    messageArgs.push_back("undetermined");
                    break;
                }
                case 0x03:
                {
                    messageID += ".AuxiliaryLogEntryAdded";
                    messageArgs.push_back(redfish_hooks::toHexStr(selData.eventData2));
                    break;
                }
                case 0x04:
                {
                    messageID += ".PEFAction";
                    messageArgs.push_back(redfish_hooks::toHexStr(selData.eventData2));
                    break;
                }
                case 0x05:
                {
                    messageID += ".TimestampClockSynch";
                    if (selData.eventData2 & 0x80)
                    {
                        messageArgs.push_back("second of pair");
                    }
                    else
                    {
                        messageArgs.push_back("first of pair");
                    }
                    break;
                }
                default:
                    return defaultMessageHook(ipmiRaw);
                    break;
            }
            break;
        }
        default:
            return defaultMessageHook(ipmiRaw);
            break;
    }

    // Log the Redfish message to the journal with the appropriate metadata
    std::string journalMsg = "BIOS POST IPMI event: " + ipmiRaw;
    if (messageArgs.empty())
    {
        log<level::INFO>(journalMsg.c_str(),
                         entry("REDFISH_MESSAGE_ID=%s", messageID.c_str()));
    }
    else
    {
        std::string messageArgsString =
            boost::algorithm::join(messageArgs, ",");
        log<level::INFO>(journalMsg.c_str(),
                         entry("REDFISH_MESSAGE_ID=%s", messageID.c_str()),
                         entry("REDFISH_MESSAGE_ARGS=%s", messageArgsString.c_str()));
    }

    return true;
}

static bool startRedfishHook(const SELData& selData, const std::string& ipmiRaw)
{
    uint8_t generatorIDLowByte = static_cast<uint8_t>(selData.generatorID);
    // Generator ID is 7 bit and LS Bit contains '1' or '0' depending on the
    // source. Refer IPMI SPEC, Table 32, SEL Event Records.
    switch (generatorIDLowByte)
    {
        case 0x01: // Check if this message is from the BIOS Generator ID
            // Let the BIOS hook handle this request
            return biosMessageHook(selData, ipmiRaw);
            break;

        case 0x2C: // Message from Intel ME
            return me::messageHook(selData, ipmiRaw);
            break;
    }

    // No hooks handled the request, so let it go to default
    return defaultMessageHook(ipmiRaw);
}

} // namespace redfish_hooks

bool checkRedfishHooks(uint16_t recordID, uint8_t recordType,
                       uint32_t timestamp, uint16_t generatorID, uint8_t evmRev,
                       uint8_t sensorType, uint8_t sensorNum, uint8_t eventType,
                       uint8_t eventData1, uint8_t eventData2,
                       uint8_t eventData3)
{
    // Save the raw IPMI string of the request
    std::string ipmiRaw;
    std::array selBytes = {static_cast<uint8_t>(recordID),
                           static_cast<uint8_t>(recordID >> 8),
                           recordType,
                           static_cast<uint8_t>(timestamp),
                           static_cast<uint8_t>(timestamp >> 8),
                           static_cast<uint8_t>(timestamp >> 16),
                           static_cast<uint8_t>(timestamp >> 24),
                           static_cast<uint8_t>(generatorID),
                           static_cast<uint8_t>(generatorID >> 8),
                           evmRev,
                           sensorType,
                           sensorNum,
                           eventType,
                           eventData1,
                           eventData2,
                           eventData3};
    redfish_hooks::toHexStr(boost::beast::span<uint8_t>(selBytes), ipmiRaw);

    // First check that this is a system event record type since that
    // determines the definition of the rest of the data
    if (recordType != ipmi::sel::systemEvent)
    {
        // OEM record type, so let it go to the SEL
        return redfish_hooks::defaultMessageHook(ipmiRaw);
    }

    // Extract the SEL data for the hook
    redfish_hooks::SELData selData = {.generatorID = generatorID,
                                      .sensorType = sensorType,
                                      .sensorNum = sensorNum,
                                      .eventType = eventType,
                                      .offset = eventData1 & 0x0F,
                                      .eventData2 = eventData2,
                                      .eventData3 = eventData3};

    return redfish_hooks::startRedfishHook(selData, ipmiRaw);
}

bool checkRedfishHooks(uint16_t generatorID, uint8_t evmRev, uint8_t sensorType,
                       uint8_t sensorNum, uint8_t eventType, uint8_t eventData1,
                       uint8_t eventData2, uint8_t eventData3)
{
    // Save the raw IPMI string of the selData
    std::string ipmiRaw;
    std::array selBytes = {static_cast<uint8_t>(generatorID),
                           static_cast<uint8_t>(generatorID >> 8),
                           evmRev,
                           sensorType,
                           sensorNum,
                           eventType,
                           eventData1,
                           eventData2,
                           eventData3};
    redfish_hooks::toHexStr(boost::beast::span<uint8_t>(selBytes), ipmiRaw);

    // Extract the SEL data for the hook
    redfish_hooks::SELData selData = {.generatorID = generatorID,
                                      .sensorType = sensorType,
                                      .sensorNum = sensorNum,
                                      .eventType = eventType,
                                      .offset = eventData1 & 0x0F,
                                      .eventData2 = eventData2,
                                      .eventData3 = eventData3};

    return redfish_hooks::startRedfishHook(selData, ipmiRaw);
}

} // namespace pw_oem::ipmi::sel

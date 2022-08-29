/*
// Copyright (c) 2018 Intel Corporation
// Copyright (c) 2022 Portwell Inc.
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

#include "oemcommands.hpp"

#include "types.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <sdbusplus/message/types.hpp>

using namespace phosphor::logging;

namespace ipmi
{
static void registerOEMFunctions() __attribute__((constructor));

static constexpr uint8_t maxEthSize = 6;
static constexpr uint8_t maxSupportedEth = 2;

static constexpr uint64_t fruEnd = 0x1ffff; // 128k EEPROM
// write rolls over within current page, need to keep mac within a page
static constexpr uint64_t fruPageSize = 0x40; // 64-Byte page size
static constexpr uint64_t macRecordSize = 6;
static constexpr uint64_t macChecksumSize = 2;
static constexpr uint16_t macChecksumShift = 0x10;

static constexpr uint16_t crcStart = 0xFFFF;

static constexpr int fruWriteCycleTime = 5500; // us

using ObjectType = boost::container::flat_map<
    std::string, boost::container::flat_map<std::string, DbusVariant>>;
using ManagedObjectType =
    boost::container::flat_map<sdbusplus::message::object_path, ObjectType>;

static constexpr uint16_t crc16Table[256] = {
	0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
	0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
	0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
	0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
	0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
	0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
	0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
	0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
	0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
	0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
	0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
	0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
	0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
	0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
	0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
	0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
	0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
	0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
	0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
	0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
	0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
	0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
	0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
	0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
	0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
	0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
	0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
	0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
	0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
	0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
	0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
	0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

static uint16_t calculateCRC16(uint16_t crc,
                               std::vector<uint8_t>::const_iterator begin,
                               std::vector<uint8_t>::const_iterator end)
{
    std::for_each(begin, end, [&crc](const uint8_t data) 
    {
        crc = (crc >> 8) ^ crc16Table[(static_cast<uint8_t>(crc) ^ data) & 0xff];
    });
    return crc;
}

bool findFruDevice(const std::shared_ptr<sdbusplus::asio::connection>& bus,
                   boost::asio::yield_context& yield, uint64_t& macOffset,
                   uint64_t& busNum, uint64_t& address)
{
    boost::system::error_code ec;

    // GetAll the objects under service FruDevice
    ec = boost::system::errc::make_error_code(boost::system::errc::success);
    auto obj = bus->yield_method_call<ManagedObjectType>(
        yield, ec, "xyz.openbmc_project.EntityManager", "/",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    if (ec)
    {
        log<level::ERR>("GetMangagedObjects failed",
                        entry("ERROR=%s", ec.message().c_str()));
        return false;
    }

    for (const auto& [path, fru] : obj)
    {
        for (const auto& [intf, propMap] : fru)
        {
            if (intf == "xyz.openbmc_project.Inventory.Item.Bmc")
            {
                auto findBus = propMap.find("FruBus");
                auto findAddress = propMap.find("FruAddress");
                auto findMacOffset = propMap.find("MacOffset");
                if (findBus == propMap.end() || findAddress == propMap.end() ||
                    findMacOffset == propMap.end())
                {
                    continue;
                }

                auto fruBus = std::get_if<uint64_t>(&findBus->second);
                auto fruAddress = std::get_if<uint64_t>(&findAddress->second);
                auto macFruOffset =
                    std::get_if<uint64_t>(&findMacOffset->second);
                if (!fruBus || !fruAddress || !macFruOffset ||
                    (*macFruOffset % fruPageSize) > 0 ||
                    *macFruOffset > fruEnd)
                {
                    log<level::ERR>("ERROR: FRU MAC config data is invalid, "
                                    "not used");
                    return false;
                }
                busNum = *fruBus;
                address = *fruAddress;
                macOffset = *macFruOffset;
                return true;
            }
        }
    }
    return false;
}

ipmi::Cc readMacFromFru(ipmi::Context::ptr ctx, uint8_t macIndex,
                    std::array<uint8_t, maxEthSize>& ethData)
{
    uint64_t macOffset = fruEnd;
    uint64_t checksumOffset = fruEnd;
    uint64_t fruBus = 0;
    uint64_t fruAddress = 0;

    if (findFruDevice(ctx->bus, ctx->yield, macOffset, fruBus, fruAddress))
    {
        macOffset += macIndex * maxEthSize;
        checksumOffset = macOffset + macChecksumShift;

        std::vector<uint8_t> writeData;
        writeData.push_back(static_cast<uint8_t>(macOffset >> 8));
        writeData.push_back(static_cast<uint8_t>(macOffset));
        std::vector<uint8_t> readBuf(macRecordSize);
        std::string i2cBus = "/dev/i2c-" + std::to_string(fruBus);
        ipmi::Cc retI2C =
            ipmi::i2cWriteRead(i2cBus, fruAddress, writeData, readBuf);
        if (retI2C == ipmi::ccSuccess)
        {
            writeData.clear();
            writeData.push_back(static_cast<uint8_t>(checksumOffset >> 8));
            writeData.push_back(static_cast<uint8_t>(checksumOffset));
            std::vector<uint8_t> checksum(macChecksumSize);
            ipmi::Cc retI2C =
                ipmi::i2cWriteRead(i2cBus, fruAddress, writeData, checksum);
            if (retI2C == ipmi::ccSuccess)
            {
                uint16_t csCalculate = calculateCRC16(crcStart,
                                                      readBuf.cbegin(),
                                                      readBuf.cend());
                uint16_t csRead;
                std::memcpy(&csRead, checksum.data(), sizeof(std::uint16_t));
                if (csCalculate == csRead)
                {
                    std::copy(readBuf.begin(), readBuf.end(), ethData.data());
                    return ipmi::ccSuccess;
                }
                return static_cast<ipmi::Cc>(IPMIPwOEMReturnCodes::ipmiCCInvalidChecksum);
            }
        }
        log<level::ERR>("ERROR: read mac fru failed, assume no eeprom is "
                        "available.");
    }
    else
    {
        log<level::ERR>(
            "ERROR: read mac fru failed, no mac info in entity-manager");
    }
    return ipmi::ccCommandNotAvailable;
}

ipmi::Cc writeMacToFru(ipmi::Context::ptr ctx, uint8_t macIndex,
                       std::array<uint8_t, maxEthSize>& ethData)
{
    uint64_t macOffset = fruEnd;
    uint64_t checksumOffset = fruEnd;
    uint64_t fruBus = 0;
    uint64_t fruAddress = 0;
    uint16_t macCheckSum = 0;

    if (findFruDevice(ctx->bus, ctx->yield, macOffset, fruBus, fruAddress))
    {
        macOffset += macIndex * maxEthSize;

        std::vector<uint8_t> writeData;
        writeData.push_back(static_cast<uint8_t>(macOffset >> 8));
        writeData.push_back(static_cast<uint8_t>(macOffset));
        std::for_each(ethData.cbegin(), ethData.cend(),
                      [&](uint8_t i) { writeData.push_back(i); });
        macCheckSum = calculateCRC16(crcStart,
                                     writeData.cbegin() + 2,
                                     writeData.cend());

        std::string i2cBus = "/dev/i2c-" + std::to_string(fruBus);
        std::vector<uint8_t> readBuf;
        ipmi::Cc ret =
            ipmi::i2cWriteRead(i2cBus, fruAddress, writeData, readBuf);

        switch (ret)
        {
            case ipmi::ccSuccess:
                // chip is write protected, if write is success but fails verify
                writeData.resize(2);
                readBuf.resize(macRecordSize); // include macHeader
                // Wait for internal write cycle to complete
                usleep(fruWriteCycleTime);
                if (ipmi::i2cWriteRead(i2cBus, fruAddress, writeData,
                                       readBuf) == ipmi::ccSuccess)
                {
                    if (std::equal(ethData.begin(), ethData.end(),
                                   readBuf.begin()))
                    {
                        checksumOffset = macOffset + macChecksumShift;
                        writeData.clear();
                        writeData.push_back(static_cast<uint8_t>(checksumOffset >> 8));
                        writeData.push_back(static_cast<uint8_t>(checksumOffset));
                        writeData.push_back(static_cast<uint8_t>(macCheckSum));
                        writeData.push_back(static_cast<uint8_t>(macCheckSum >> 8));
                        readBuf.clear();
                        ipmi::Cc ret =
                            ipmi::i2cWriteRead(i2cBus, fruAddress, writeData, readBuf);
                        if (ret == ipmi::ccSuccess)
                        {
                            usleep(fruWriteCycleTime);
                        }
                        else
                        {
                            log<level::INFO>("ERROR: failed to write checksum.");
                            return ipmi::ccCommandNotAvailable;
                        }
                        return ret;
                    }
                    log<level::INFO>("INFO: write mac fru verify failed, "
                                     "fru may be write protected.");
                }
                return ipmi::ccCommandNotAvailable;
            default: // assumes no actual eeprom for other failure
                log<level::ERR>("ERROR: write mac fru failed, assume no "
                                "eeprom is available.");
                break;
        }
    }
    // no FRU eeprom found
    return ipmi::ccDestinationUnavailable;
}

/** @brief implements the set BMC MAC command
 *  @param ethIndex         - Index of ethernet device
 *  @param ethData          - 6 bytes MAC address
 *
 *  @returns ipmi completion code
 */
ipmi::RspType<> ipmiOemSetBmcMac(ipmi::Context::ptr ctx, uint8_t ethIndex,
                                 std::array<uint8_t, maxEthSize> ethData)
{
    if (ethIndex >= maxSupportedEth)
    {
        return ipmi::responseParmOutOfRange();
    }

    ipmi::Cc ret = writeMacToFru(ctx, ethIndex, ethData);
    if (ret != ipmi::ccSuccess)
    {
        return response(ret);
    }

    return ipmi::responseSuccess();
}

/** @brief implements the set BMC MAC command
 *  @param ethIndex         - Index of ethernet device
 *
 *  @returns ipmi completion code and 6 bytes mac address if success
 */
ipmi::RspType<std::array<uint8_t, maxEthSize>> 
    ipmiOemGetBmcMac(ipmi::Context::ptr ctx, uint8_t ethIndex)
{
    if (ethIndex >= maxSupportedEth)
    {
        return ipmi::responseParmOutOfRange();
    }

    std::array<uint8_t, maxEthSize> macAddress;
    ipmi::Cc ret = readMacFromFru(ctx, ethIndex, macAddress);
    if (ret != ipmi::ccSuccess)
    {
        return response(ret);
    }

    return ipmi::responseSuccess(macAddress);
}

static void registerOEMFunctions(void)
{
    // <Set BMC MAC address>
    registerHandler(ipmi::prioOemBase, ipmi::pw::netFnGeneral,
                    ipmi::pw::general::cmdSetBmcMac,
                    ipmi::Privilege::Admin, ipmi::ipmiOemSetBmcMac);

    // <Get BMC MAC address>
    registerHandler(ipmi::prioOemBase, ipmi::pw::netFnGeneral,
                    ipmi::pw::general::cmdGetBmcMac,
                    ipmi::Privilege::Admin, ipmi::ipmiOemGetBmcMac);
}

} // namespace ipmi

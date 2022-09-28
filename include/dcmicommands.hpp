/*
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
#pragma once

#include <boost/container/flat_map.hpp>
#include <ipmid/api.hpp>

#include <map>
#include <string>
#include <vector>

namespace dcmi
{

enum Commands
{
    // Get capability bits
    GET_CAPABILITIES = 0x01,
    GET_POWER_READING = 0x02,
    GET_POWER_LIMIT = 0x03,
    SET_POWER_LIMIT = 0x04,
    APPLY_POWER_LIMIT = 0x05,
    GET_ASSET_TAG = 0x06,
    GET_SENSOR_INFO = 0x07,
    SET_ASSET_TAG = 0x08,
    GET_MGMNT_CTRL_ID_STR = 0x09,
    SET_MGMNT_CTRL_ID_STR = 0x0A,
    GET_TEMP_READINGS = 0x10,
    SET_CONF_PARAMS = 0x12,
    GET_CONF_PARAMS = 0x13,
};

static constexpr auto groupExtId = 0xDC;
static constexpr auto assetTagMaxOffset = 62;
static constexpr auto assetTagMaxSize = 63;
static constexpr auto maxBytes = 16;
static constexpr size_t maxCtrlIdStrLen = 63;

/** @brief Read the object tree to fetch the object path which is the baseboard
 *         FRU
 *
 *  @param[in,out] fruPath - FRU object path
 *
 *  @return On success return the object path which is the baseboard FRU.
 */
ipmi_ret_t getBaseBoardFruPath(ipmi::Context::ptr ctx, std::string& fruPath);

/** @brief Read the asset tag from baseboard FRU
 *
 *  @param[in]     fruPath  - FRU object path
 *  @param[in,out] assetTag - Asset tag
 *
 *  @return On success return the asset tag.
 */
ipmi_ret_t readAssetTag(ipmi::Context::ptr ctx, std::string fruPath,
                        std::string& assetTag);

/** @brief Write the asset tag to the baseboard FRU
 *
 *  @param[in] fruPath  - FRU object path
 *  @param[in] assetTag - Asset Tag to be written to the baseboard FRU.
 */
ipmi_ret_t writeAssetTag(ipmi::Context::ptr ctx, std::string fruPath,
                         std::string assetTag);

} // namespace dcmi

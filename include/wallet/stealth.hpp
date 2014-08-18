/**
 * Copyright (c) 2011-2013 libwallet developers (see AUTHORS)
 *
 * This file is part of libwallet.
 *
 * libwallet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBWALLET_STEALTH_HPP
#define LIBWALLET_STEALTH_HPP

#include <algorithm>
#include <cstdint>
#include <bitcoin/bitcoin.hpp>
#include <wallet/define.hpp>

namespace libwallet {

BCW_API typedef std::vector<bc::ec_point> pubkey_list;

BCW_API struct stealth_info
{
    bc::ec_point ephem_pubkey;
    bc::stealth_bitfield bitfield;
};

// Supports testnet and mainnet addresses but not prefix > 0
class stealth_address
{
public:
    static const uint8_t max_prefix_bits = sizeof(uint32_t)* bc::byte_bits;
    enum flags : uint8_t
    {
        none = 0x00,
        reuse_key = 0x01
    };
    enum network : uint8_t
    {
        mainnet = 0x2a,
        testnet = 0x2b
    };

    // Construction
    BCW_API stealth_address();
    BCW_API stealth_address(const bc::stealth_prefix& prefix,
        const bc::ec_point& scan_pubkey, const pubkey_list& spend_pubkeys,
        uint8_t signatures, bool testnet);

    // Serialization
    BCW_API std::string encoded() const;
    BCW_API bool set_encoded(const std::string& encoded_address);
    BCW_API bool valid() const;

    // Properties
    BCW_API const bc::stealth_prefix& get_prefix() const;
    BCW_API const bc::ec_point& get_scan_pubkey() const;
    BCW_API uint8_t get_signatures() const;
    BCW_API const pubkey_list& get_spend_pubkeys() const;
    BCW_API bool get_testnet() const;

protected:
    const bool get_reuse_key() const;
    const uint8_t get_options() const;
    const uint8_t get_version() const;

    bool valid_ = false;
    bool testnet_ = false;
    uint8_t signatures_ = 0;
    bc::ec_point scan_pubkey_;
    pubkey_list spend_pubkeys_;
    bc::stealth_prefix prefix_;
};

// See libbitcoin::extract()
BCW_API bool extract_stealth_info(stealth_info& info,
    const bc::script_type& output_script);
BCW_API bc::ec_point initiate_stealth(
    const bc::ec_secret& ephem_secret, const bc::ec_point& scan_pubkey,
    const bc::ec_point& spend_pubkey);
BCW_API bc::ec_secret shared_secret(const bc::ec_secret& secret,
    const bc::ec_point& point);
BCW_API bc::ec_point uncover_stealth(
    const bc::ec_point& ephem_pubkey, const bc::ec_secret& scan_secret,
    const bc::ec_point& spend_pubkey);
BCW_API bc::ec_secret uncover_stealth_secret(
    const bc::ec_point& ephem_pubkey, const bc::ec_secret& scan_secret,
    const bc::ec_secret& spend_secret);

BCW_API bc::stealth_prefix bytes_to_prefix(const uint32_t prefix_number_bits,
    const bc::data_chunk& bytes);
BCW_API bc::data_chunk prefix_to_bytes(const bc::stealth_prefix& prefix);

} // namespace libwallet

#endif
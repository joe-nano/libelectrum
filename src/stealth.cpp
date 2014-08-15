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
#include <wallet/stealth.hpp>

#include <cstdint>
#include <bitcoin/bitcoin.hpp>

using namespace bc;

namespace libwallet {

constexpr uint8_t options_size = 1;
constexpr uint8_t checksum_size = 4;
constexpr uint8_t version_size = 1;
constexpr uint8_t nonce_size = 4;
constexpr uint8_t pubkey_size = 33;
constexpr uint8_t number_keys_size = 1;
constexpr uint8_t number_sigs_size = 1;
constexpr uint8_t prefix_length_size = 1;
constexpr uint8_t min_prefix_size = 1;
constexpr size_t max_spend_key_count = sizeof(uint8_t)* byte_size;

// wiki.unsystem.net/index.php/DarkWallet/Stealth#Address_format
// [version:1=0x2a][options:1][scan_pubkey:33][N:1][spend_pubkey_1:33]..
// [spend_pubkey_N:33][number_signatures:1][prefix_number_bits:1]
// [prefix:prefix_number_bits / 8, round up]
// Estimate assumes N = 0 and prefix_length = 0:
constexpr size_t min_address_size = version_size + options_size + pubkey_size +
    number_keys_size + number_sigs_size + prefix_length_size + min_prefix_size;

BCW_API stealth_address::stealth_address()
    : valid_(false)
{
}

BCW_API stealth_address::stealth_address(const stealth_prefix& prefix,
    const ec_point& scan_pubkey, const pubkey_list& spend_pubkeys, 
    uint8_t signatures, bool testnet)
{
    // spend_pubkeys is guarded against a size greater than 255.
    // TODO: shouldn't signatures be limited to <= spend_pubkeys_size?
    const auto spend_pubkeys_size = spend_pubkeys.size();
    if (spend_pubkeys_size > max_spend_key_count /*|| 
        signatures <= spend_pubkeys_size*/)
        return;

    // what I wouldn't give for a ternary :).
    if (signatures == 0)
        signatures_ = static_cast<uint8_t>(spend_pubkeys_size);
    else
        signatures_ = signatures;

    testnet_ = testnet;
    scan_pubkey_ = scan_pubkey;
    spend_pubkeys_ = spend_pubkeys;
    valid_ = true;
}

BCW_API std::string stealth_address::encoded() const
{
    if (!valid_)
        return std::string();

    data_chunk raw_address;
    raw_address.push_back(get_version());
    raw_address.push_back(get_options());
    extend_data(raw_address, scan_pubkey_);

    // spend_pubkeys must be guarded against a size greater than 255.
    auto number_spend_pubkeys = static_cast<uint8_t>(spend_pubkeys_.size());
    raw_address.push_back(number_spend_pubkeys);

    // Serialize the spend keys, excluding any that match the scan key.
    for (const ec_point& pubkey: spend_pubkeys_)
        if (pubkey != scan_pubkey_)
            extend_data(raw_address, pubkey);

    raw_address.push_back(signatures_);

    // The prefix must be guarded against a size greater than 32
    // so that the bitfield can convert into uint32_t, which also ensures
    // that the number of bits doesn't exceed uint8_t.
    auto prefix_number_bits = static_cast<uint8_t>(prefix_.size());
    auto prefix_bit_field = static_cast<uint32_t>(prefix_.to_ulong());

    // Prefix not yet supported on server!
    BITCOIN_ASSERT(prefix_number_bits == 0);
    if (prefix_number_bits != 0)
        return std::string();
    raw_address.push_back(prefix_number_bits);

    // Prefix not yet supported on server!
    // TODO: fix conversion (4 bytes and endianness).
    //raw_address.push_back(prefix_bit_field);

    append_checksum(raw_address);
    return encode_base58(raw_address);
}

BCW_API bool stealth_address::set_encoded(const std::string& encoded_address)
{
    valid_ = false;
    auto raw_address = decode_base58(encoded_address);
    if (!verify_checksum(raw_address))
        return valid_;

    // Delete checksum bytes.
    BITCOIN_ASSERT(raw_address.size() >= checksum_size);
    auto checksum_begin = raw_address.end() - checksum_size;
    raw_address.erase(checksum_begin, raw_address.end());
    BITCOIN_ASSERT(raw_address.size() >= min_address_size);

    // Start walking the array.
    auto iter = raw_address.begin();

    // [version:1 = 0x2a]
    auto version = *iter;
    if (version != network::mainnet && version != network::testnet)
        return valid_;
    ++iter;

    // [options:1]
    auto options = *iter;
    if (options != flags::none && options != flags::reuse_key)
        return valid_;
    ++iter;

    // Delayed assignment until we can't fail.
    testnet_ = (version == network::testnet);

    // [scan_pubkey:33]
    auto scan_key_begin = iter;
    iter += pubkey_size;
    scan_pubkey_ = ec_point(scan_key_begin, iter);

    // [N:1]
    auto number_spend_pubkeys = *iter;
    ++iter;

    auto buffer_size = min_address_size + number_spend_pubkeys * pubkey_size;
    BITCOIN_ASSERT(raw_address.size() >= buffer_size);

    // We don't explicitly save 'reuse', instead we add to spend_pubkeys_.
    if (options == flags::reuse_key)
        spend_pubkeys_.emplace_back(scan_pubkey_);

    // [spend_pubkey_1:33]..[spend_pubkey_N:33]
    for (auto key = 0; key < number_spend_pubkeys; ++key)
    {
        auto spend_key_begin = iter;
        iter += pubkey_size;
        spend_pubkeys_.emplace_back(ec_point(spend_key_begin, iter));
    }

    // [number_signatures:1]
    signatures_ = *iter;
    ++iter;

    // [prefix_number_bits:1]
    uint8_t prefix_number_bits = *iter;
    prefix_.resize(prefix_number_bits);
    ++iter;

    // [prefix:prefix_number_bits / 8, round up]
    auto prefix_bytes = (prefix_number_bits + (byte_size-1)) / byte_size;
    auto prefix_blocks = prefix_.num_blocks();
    BITCOIN_ASSERT(prefix_bytes == prefix_blocks);
    buffer_size += prefix_blocks;
    BITCOIN_ASSERT(raw_address.size() >= buffer_size);

    // Prefix not yet supported on server!
    BITCOIN_ASSERT(prefix_number_bits == 0);
    if (prefix_number_bits != 0)
        return valid_;

    valid_ = true;
    return valid_;
}

BCW_API bool stealth_address::valid() const
{
    return false;
}

BCW_API const stealth_prefix& stealth_address::get_prefix() const
{
    return prefix_;
}

BCW_API const ec_point& stealth_address::get_scan_pubkey() const
{
    return scan_pubkey_;
}

BCW_API uint8_t stealth_address::get_signatures() const
{
    return signatures_;
}

BCW_API const pubkey_list& stealth_address::get_spend_pubkeys() const
{
    return spend_pubkeys_;
}

BCW_API bool stealth_address::get_testnet() const
{
    return testnet_;
}

const bool stealth_address::get_reuse_key() const
{
    // If the spend_pubkeys_ contains the scan_pubkey_ then the key is reused.
    return std::find(spend_pubkeys_.begin(), spend_pubkeys_.end(), 
        scan_pubkey_) != spend_pubkeys_.end();
}

const uint8_t stealth_address::get_options() const
{
    if (get_reuse_key())
        return flags::reuse_key;
    else
        return flags::none;
}

const uint8_t stealth_address::get_version() const
{
    if (testnet_)
        return network::testnet;
    else
        return network::mainnet;
}

BCW_API bool extract_stealth_info(stealth_info& info,
    const bc::script_type& output_script)
{
    if (output_script.type() == payment_type::stealth_info &&
        output_script.operations().size() > 1)
    {
        const auto& data = output_script.operations()[1].data;
        auto valid = data.size() == version_size + nonce_size + pubkey_size;
        if (valid)
        {
            info.bitfield = calculate_stealth_bitfield(data);
            info.ephem_pubkey.assign(data.begin() + version_size + nonce_size,
                data.end());
            return true;
        }
    }

    return false;
};

BCW_API ec_point initiate_stealth(
    const ec_secret& ephem_secret, const ec_point& scan_pubkey,
    const ec_point& spend_pubkey)
{
    ec_point final = spend_pubkey;
    ec_secret shared = shared_secret(ephem_secret, scan_pubkey);
    bool success = ec_add(final, shared);
    BITCOIN_ASSERT(success);
    return final;
}

BCW_API ec_secret shared_secret(const ec_secret& secret, 
    const ec_point& point)
{
    ec_point final = point;
    bool success = ec_multiply(final, secret);
    BITCOIN_ASSERT(success);
    return sha256_hash(final);
}

BCW_API ec_point uncover_stealth(
    const ec_point& ephem_pubkey, const ec_secret& scan_secret,
    const ec_point& spend_pubkey)
{
    ec_point final = spend_pubkey;
    ec_secret shared = shared_secret(scan_secret, ephem_pubkey);
    bool success = ec_add(final, shared);
    BITCOIN_ASSERT(success);
    return final;
}

BCW_API ec_secret uncover_stealth_secret(
    const ec_point& ephem_pubkey, const ec_secret& scan_secret,
    const ec_secret& spend_secret)
{
    ec_secret final = spend_secret;
    ec_secret shared = shared_secret(scan_secret, ephem_pubkey);
    bool success = ec_add(final, shared);
    BITCOIN_ASSERT(success);
    return final;
}

} // namespace libwallet


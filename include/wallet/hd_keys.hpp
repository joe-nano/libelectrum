/*
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
#ifndef LIBWALLET_HD_KEYS_HPP
#define LIBWALLET_HD_KEYS_HPP

#include <bitcoin/address.hpp>
#include <bitcoin/utility/elliptic_curve_key.hpp>
#include <wallet/define.hpp>

namespace libwallet {

using namespace libbitcoin;

typedef std::array<uint8_t, 4> ser32_type;
typedef std::array<uint8_t, 32> chain_code_type;

constexpr uint32_t first_hardened_key = 1 << 31;

/**
 * Key derivation information used in the serialization format.
 */
struct BCW_API hd_key_lineage
{
    bool testnet;
    uint8_t depth;
    ser32_type parent_fingerprint;
    uint32_t child_number;
};

/**
 * An extended public key, as defined by BIP 32.
 */
class hd_public_key
{
public:
    BCW_API hd_public_key();
    BCW_API hd_public_key(const data_chunk& public_key,
        const chain_code_type& chain_code, hd_key_lineage lineage);

    BCW_API bool valid() const;

    BCW_API const data_chunk& public_key() const;
    BCW_API const chain_code_type& chain_code() const;
    BCW_API const hd_key_lineage& lineage() const;
    BCW_API std::string serialize() const;
    BCW_API ser32_type fingerprint() const;
    BCW_API payment_address address() const;

    BCW_API hd_public_key generate_public_key(uint32_t i);

protected:
    bool valid_;
    data_chunk K_; // EC point
    chain_code_type c_;
    hd_key_lineage lineage_;
};

/**
 * An extended private key, as defined by BIP 32.
 */
class hd_private_key
  : public hd_public_key
{
public:
    BCW_API hd_private_key();
    BCW_API hd_private_key(const secret_parameter& private_key,
        const chain_code_type& chain_code, hd_key_lineage lineage);
    BCW_API hd_private_key(const data_chunk& seed, bool testnet=false);

    BCW_API const secret_parameter& private_key() const;
    BCW_API std::string serialize() const;

    BCW_API hd_private_key generate_private_key(uint32_t i);
    BCW_API hd_public_key generate_public_key(uint32_t i);

protected:
    secret_parameter k_;
};

} // namespace libwallet

#endif


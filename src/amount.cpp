/*
 * Copyright (c) 2011-2014 libwallet developers (see AUTHORS)
 *
 * This file is part of libwallet.
 *
 * libwallet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <wallet/amount.hpp>
#include <sstream>
#include <boost/algorithm/string.hpp>

namespace libwallet {

static bool is_digit(const char c)
{
    return '0' <= c && c <= '9';
}

BCW_API uint64_t parse_amount(const std::string& amount,
    unsigned decmial_places)
{
    auto i = amount.begin();
    uint64_t value = 0;
    unsigned places = 0;

    while (amount.end() != i && is_digit(*i))
    {
        value = 10*value + (*i - '0');
        ++i;
    }
    if (amount.end() != i && '.' == *i)
    {
        ++i;
        while (amount.end() != i && is_digit(*i))
        {
            if (places < decmial_places)
                value = 10*value + (*i - '0');
            else if (places == decmial_places && '5' <= *i)
                value += 1;
            ++places;
            ++i;
        }
    }
    while (places < decmial_places)
    {
        value *= 10;
        ++places;
    }
    if (amount.end() != i)
        return invalid_amount;
    return value;
}

BCW_API std::string format_amount(uint64_t amount, unsigned decimal_places)
{
    // Get the integer and fractional parts:
    uint64_t factor = 1;
    for (unsigned i = 0; i < decimal_places; ++i)
        factor *= 10;
    uint64_t int_part = amount / factor;
    uint64_t decimal_part = amount % factor;
    // Format as a fixed-point number:
    std::ostringstream stream;
    stream << int_part << '.';
    stream << std::setw(decimal_places) << std::setfill('0') << decimal_part;
    // Trim trailing zeros:
    auto string = stream.str();
    boost::algorithm::trim_right_if(string, [](char c){ return '0' == c; });
    boost::algorithm::trim_right_if(string, [](char c){ return '.' == c; });
    return string;
}

} // namespace libwallet

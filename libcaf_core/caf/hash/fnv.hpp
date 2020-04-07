/******************************************************************************
 *                       ____    _    _____                                   *
 *                      / ___|  / \  |  ___|    C++                           *
 *                     | |     / _ \ | |_       Actor                         *
 *                     | |___ / ___ \|  _|      Framework                     *
 *                      \____/_/   \_|_|                                      *
 *                                                                            *
 * Copyright 2011-2020 Dominik Charousset                                     *
 *                                                                            *
 * Distributed under the terms and conditions of the BSD 3-Clause License or  *
 * (at your option) under the terms and conditions of the Boost Software      *
 * License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.       *
 *                                                                            *
 * If you did not receive a copy of the license files, see                    *
 * http://opensource.org/licenses/BSD-3-Clause and                            *
 * http://www.boost.org/LICENSE_1_0.txt.                                      *
 ******************************************************************************/

#pragma once

#include <cstdint>
#include <string>
#include <type_traits>

#include "caf/allowed_unsafe_message_type.hpp"
#include "caf/detail/ieee_754.hpp"
#include "caf/detail/type_traits.hpp"
#include "caf/meta/annotation.hpp"
#include "caf/meta/save_callback.hpp"
#include "caf/span.hpp"
#include "caf/string_view.hpp"

namespace caf::hash {

/// Non-cryptographic hash algorithm (variant 1a) named after Glenn Fowler,
/// Landon Curt Noll, and Kiem-Phong Vo.
///
/// For more details regarding the public domain algorithm, see:
/// - https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
/// - http://www.isthe.com/chongo/tech/comp/fnv/index.html
///
/// @tparam T One of `uint32_t`, `uint64_t`, or `size_t`.
template <class T>
class fnv {
public:
  static_assert(sizeof(T) == 4 || sizeof(T) == 8);

  using result_type = void;

  static constexpr bool reads_state = true;

  static constexpr bool writes_state = false;

  constexpr fnv() noexcept : value(init()) {
    // nop
  }

  template <class Integral>
  std::enable_if_t<std::is_integral<Integral>::value>
  apply(Integral x) noexcept {
    auto begin = reinterpret_cast<const uint8_t*>(&x);
    append(begin, begin + sizeof(Integral));
  }

  void apply(bool x) noexcept {
    auto tmp = static_cast<uint8_t>(x);
    apply(tmp);
  }

  void apply(float x) noexcept {
    apply(detail::pack754(x));
  }

  void apply(double x) noexcept {
    apply(detail::pack754(x));
  }

  void apply(string_view x) noexcept {
    auto begin = reinterpret_cast<const uint8_t*>(x.data());
    append(begin, begin + x.size());
  }

  template <class U>
  void apply(span<U> xs) noexcept {
    for (const auto& x : xs)
      (*this)(x);
  }

  template <class Enum>
  std::enable_if_t<std::is_enum<Enum>::value> apply(Enum x) noexcept {
    return apply(static_cast<std::underlying_type_t<Enum>>(x));
  }

  void begin_sequence(size_t) {
    // nop
  }

  void end_sequence() {
    // nop
  }

  /// Convenience function for computing an FNV1a hash value for given
  /// arguments in one shot.
  template <class... Ts>
  static T compute(Ts&&... xs) {
    fnv f;
    f(std::forward<Ts>(xs)...);
    return f.value;
  }

  template <class... Ts>
  void operator()(Ts&&... xs) {
    (do_apply(xs), ...);
  }

  T value;

private:
  static constexpr T init() {
    if constexpr (sizeof(T) == 4)
      return 0x811C9DC5u;
    else
      return 0xCBF29CE484222325ull;
  }

  void append(const uint8_t* begin, const uint8_t* end) {
    if constexpr (sizeof(T) == 4)
      while (begin != end)
        value = (*begin++ ^ value) * 0x01000193u;
    else
      while (begin != end)
        value = (*begin++ ^ value) * 1099511628211ull;
  }

  template <class Tuple, size_t... Is>
  void apply_tuple(const Tuple& xs, std::index_sequence<Is...>) {
    (*this)(std::get<Is>(xs)...);
  }

  template <class U, size_t... Is>
  void apply_array(const U* xs, std::index_sequence<Is...>) {
    (*this)(xs[Is]...);
  }

  template <class U>
  std::enable_if_t<meta::is_annotation<U>::value> do_apply(T& x) {
    if constexpr (meta::is_save_callback<U>::value)
      x.fun();
  }

  void do_apply(const std::string& x) {
    apply(string_view{x});
  }

  template <class U>
  std::enable_if_t<!meta::is_annotation<U>::value> do_apply(const U& x) {
    if constexpr (std::is_empty<U>::value
                  || is_allowed_unsafe_message_type<U>::value) {
      // skip element
    } else if constexpr (detail::can_apply_v<fnv, decltype(x)>) {
      apply(x);
    } else if constexpr (std::is_array<U>::value) {
      std::make_index_sequence<std::extent<U>::value> seq;
      apply_array(x, seq);
    } else if constexpr (detail::is_stl_tuple_type<U>::value) {
      std::make_index_sequence<std::tuple_size<U>::value> seq;
      apply_tuple(x, seq);
    } else if constexpr (detail::is_map_like<U>::value) {
      begin_sequence(x.size());
      for (const auto& kvp : x) {
        (*this)(kvp.first, kvp.second);
      }
      end_sequence();
    } else if constexpr (detail::is_list_like<U>::value) {
      begin_sequence(x.size());
      for (const auto& value : x) {
        (*this)(value);
      }
      end_sequence();
    } else {
      static_assert(detail::is_inspectable<fnv, U>::value);
      // We require that the implementation for `inspect` does not modify its
      // arguments when passing a reading inspector.
      auto& mutable_x = const_cast<U&>(x);
      inspect(*this, mutable_x);
    }
  }
};

} // namespace caf::hash

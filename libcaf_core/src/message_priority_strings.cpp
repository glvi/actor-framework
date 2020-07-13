// clang-format off
// DO NOT EDIT: this file is auto-generated by caf-generate-enum-strings.
// Run the target update-enum-strings if this file is out of sync.
#include "caf/config.hpp"

CAF_PUSH_DEPRECATED_WARNING

#include "caf/message_priority.hpp"

#include <string>

namespace caf {

std::string to_string(message_priority x) {
  switch(x) {
    default:
      return "???";
    case message_priority::high:
      return "high";
    case message_priority::normal:
      return "normal";
  };
}

} // namespace caf

CAF_POP_WARNINGS

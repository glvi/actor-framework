// clang-format off
// DO NOT EDIT: this file is auto-generated by caf-generate-enum-strings.
// Run the target update-enum-strings if this file is out of sync.
#include "caf/config.hpp"

CAF_PUSH_DEPRECATED_WARNING

#include "caf/sec.hpp"

#include <string>

namespace caf {

std::string to_string(sec x) {
  switch(x) {
    default:
      return "???";
    case sec::none:
      return "none";
    case sec::unexpected_message:
      return "unexpected_message";
    case sec::unexpected_response:
      return "unexpected_response";
    case sec::request_receiver_down:
      return "request_receiver_down";
    case sec::request_timeout:
      return "request_timeout";
    case sec::no_such_group_module:
      return "no_such_group_module";
    case sec::no_actor_published_at_port:
      return "no_actor_published_at_port";
    case sec::unexpected_actor_messaging_interface:
      return "unexpected_actor_messaging_interface";
    case sec::state_not_serializable:
      return "state_not_serializable";
    case sec::unsupported_sys_key:
      return "unsupported_sys_key";
    case sec::unsupported_sys_message:
      return "unsupported_sys_message";
    case sec::disconnect_during_handshake:
      return "disconnect_during_handshake";
    case sec::cannot_forward_to_invalid_actor:
      return "cannot_forward_to_invalid_actor";
    case sec::no_route_to_receiving_node:
      return "no_route_to_receiving_node";
    case sec::failed_to_assign_scribe_from_handle:
      return "failed_to_assign_scribe_from_handle";
    case sec::failed_to_assign_doorman_from_handle:
      return "failed_to_assign_doorman_from_handle";
    case sec::cannot_close_invalid_port:
      return "cannot_close_invalid_port";
    case sec::cannot_connect_to_node:
      return "cannot_connect_to_node";
    case sec::cannot_open_port:
      return "cannot_open_port";
    case sec::network_syscall_failed:
      return "network_syscall_failed";
    case sec::invalid_argument:
      return "invalid_argument";
    case sec::invalid_protocol_family:
      return "invalid_protocol_family";
    case sec::cannot_publish_invalid_actor:
      return "cannot_publish_invalid_actor";
    case sec::cannot_spawn_actor_from_arguments:
      return "cannot_spawn_actor_from_arguments";
    case sec::end_of_stream:
      return "end_of_stream";
    case sec::no_context:
      return "no_context";
    case sec::unknown_type:
      return "unknown_type";
    case sec::no_proxy_registry:
      return "no_proxy_registry";
    case sec::runtime_error:
      return "runtime_error";
    case sec::remote_linking_failed:
      return "remote_linking_failed";
    case sec::cannot_add_upstream:
      return "cannot_add_upstream";
    case sec::upstream_already_exists:
      return "upstream_already_exists";
    case sec::invalid_upstream:
      return "invalid_upstream";
    case sec::cannot_add_downstream:
      return "cannot_add_downstream";
    case sec::downstream_already_exists:
      return "downstream_already_exists";
    case sec::invalid_downstream:
      return "invalid_downstream";
    case sec::no_downstream_stages_defined:
      return "no_downstream_stages_defined";
    case sec::stream_init_failed:
      return "stream_init_failed";
    case sec::invalid_stream_state:
      return "invalid_stream_state";
    case sec::unhandled_stream_error:
      return "unhandled_stream_error";
    case sec::bad_function_call:
      return "bad_function_call";
    case sec::feature_disabled:
      return "feature_disabled";
    case sec::cannot_open_file:
      return "cannot_open_file";
    case sec::socket_invalid:
      return "socket_invalid";
    case sec::socket_disconnected:
      return "socket_disconnected";
    case sec::socket_operation_failed:
      return "socket_operation_failed";
    case sec::unavailable_or_would_block:
      return "unavailable_or_would_block";
    case sec::incompatible_versions:
      return "incompatible_versions";
    case sec::incompatible_application_ids:
      return "incompatible_application_ids";
    case sec::malformed_basp_message:
      return "malformed_basp_message";
    case sec::serializing_basp_payload_failed:
      return "serializing_basp_payload_failed";
    case sec::redundant_connection:
      return "redundant_connection";
    case sec::remote_lookup_failed:
      return "remote_lookup_failed";
    case sec::no_tracing_context:
      return "no_tracing_context";
    case sec::all_requests_failed:
      return "all_requests_failed";
    case sec::connection_timeout:
      return "connection_timeout";
  };
}

} // namespace caf

CAF_POP_WARNINGS

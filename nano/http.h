/*
 * nano library
 *
 * Copyright (C) 2022, Meta-Sonic
 * All rights reserved.
 *
 * Proprietary and confidential.
 * Any unauthorized copying, alteration, distribution, transmission, performance,
 * display or other use of this material is strictly prohibited.
 *
 * Written by Alexandre Arsenault <alx.arsenault@gmail.com>
 */

#pragma once

/*!
 * @file      nano/http.h
 * @brief     nano http
 * @copyright Copyright (C) 2022, Meta-Sonic
 * @author    Alexandre Arsenault alx.arsenault@gmail.com
 * @date      Created 26/07/2022
 */

#include <nano/common.h>
#include <cctype>
#include <string>
#include <string_view>
#include <functional>
#include <memory>

#include <vector>

NANO_CLANG_DIAGNOSTIC_PUSH()
NANO_CLANG_DIAGNOSTIC(warning, "-Weverything")
NANO_CLANG_DIAGNOSTIC(ignored, "-Wc++98-compat")

namespace nano::http {

///
enum class method : std::uint64_t {
  /// The HTTP GET method requests a representation of the specified resource.
  /// Requests using GET should only be used to request data (they shouldn't include data).
  /// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET
  get,

  /// The HTTP POST method sends data to the server.
  /// The type of the body of the request is indicated by the Content-Type header.
  /// The difference between PUT and POST is that PUT is idempotent:
  /// calling it once or several times successively has the same effect (that is no side effect),
  /// where successive identical POST may have additional effects, like passing an order several times.
  /// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
  post,

  /// The HTTP PUT request method creates a new resource or replaces a representation of
  /// the target resource with the request payload.
  /// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/PUT
  put,

  /// The HTTP PATCH request method applies partial modifications to a resource.
  /// A PATCH request is considered a set of instructions on how to modify a resource.
  /// Contrast this with PUT; which is a complete representation of a resource.
  /// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/PATCH
  patch,

  /// The HTTP DELETE request method deletes the specified resource.
  /// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/DELETE
  del,

  /// The HTTP HEAD method requests the headers that would be returned if the HEAD request's
  /// URL was instead requested with the HTTP GET method. For example, if a URL might produce
  /// a large download,a HEAD request could read its Content-Length header to check the filesize
  /// without actually downloading the file.
  ///
  /// @warning A response to a HEAD method should not have a body.
  ///          If it has one anyway, that body must be ignored: any representation headers that
  ///          might describe the erroneous body are instead assumed to describe the response
  ///          which a similar GET request would have received.
  /// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD
  head
};

///
enum class scheme { http, https };

enum class status_code {
  invalid = 0,

  // informational.
  continued = 100,
  switching_protocols = 101,
  processing = 102,
  early_hints = 103,

  // sucess.
  ok = 200,
  created = 201,
  accepted = 202,
  non_authoritative_information = 203,
  no_content = 204,
  reset_content = 205,
  partial_content = 206,
  multi_status = 207,
  already_reported = 208,
  im_used = 226,

  // redirection.
  multiple_choices = 300,
  moved_permanently = 301,
  found = 302,
  see_other = 303,
  not_modified = 304,
  use_proxy = 305,
  temporary_redirect = 307,
  permanent_redirect = 308,

  // client errors.
  bad_request = 400,
  unauthorized = 401,
  payment_required = 402,
  forbidden = 403,
  not_found = 404,
  method_not_allowed = 405,
  not_acceptable = 406,
  proxy_authentication_required = 407,
  request_timeout = 408,
  conflict = 409,
  gone = 410,
  length_required = 411,
  precondition_failed = 412,
  payload_too_large = 413,
  uri_too_long = 414,
  unsupported_media_type = 415,
  range_not_satisfiable = 416,
  expectation_failed = 417,
  im_a_teapot = 418,
  misdirected_request = 421,
  unprocessable_entity = 422,
  locked = 423,
  failed_dependency = 424,
  too_early = 425,
  upgrade_required = 426,
  precondition_required = 428,
  too_many_requests = 429,
  request_header_fields_too_large = 431,
  unavailable_for_legal_reasons = 451,

  // server errors.
  internal_server_error = 500,
  not_implemented = 501,
  bad_gateway = 502,
  service_unavailable = 503,
  gateway_timeout = 504,
  http_version_not_supported = 505,
  variant_also_negotiates = 506,
  insufficient_storage = 507,
  loop_detected = 508,
  not_extended = 510,
  network_authentication_required = 511
};

enum class error_code {
  none,

  unknown,
  cancelled,
  bad_url,
  timed_out,
  unsupported_url,
  cannot_find_host,
  cannot_connect_to_host,
  network_connection_lost,
  dns_lookup_failed,
  http_too_many_redirects,
  resource_unavailable,
  not_connected_to_internet,
  redirect_to_non_existent_location,
  bad_server_response,
  user_cancelled_authentication,
  user_authentication_required,
  zero_byte_resource,
  cannot_decode_raw_data,
  cannot_decode_content_data,
  cannot_parse_response,
  app_transport_security_requires_secure_connection,
  file_does_not_exist,
  file_is_directory,
  no_permissions_to_read_file,
  data_length_exceeds_maximum,
  file_outside_safe_area,

  // ssl errors.

  secure_connection_failed,
  server_certificate_has_bad_date,
  server_certificate_untrusted,
  server_certificate_has_unknown_root,
  server_certificate_not_yet_valid,
  client_certificate_rejected,
  client_certificate_required,
  cannot_load_from_network
};

///
struct parameter {
  std::string name;
  std::string value;
};

struct header_field {
  std::string name;
  std::string value;
};

class response;

/// @struct status
struct status {
  status() NANO_NOEXCEPT = default;
  NANO_INLINE_CXPR status(int status) NANO_NOEXCEPT;
  NANO_INLINE_CXPR status(status_code c) NANO_NOEXCEPT;

  ~status() NANO_NOEXCEPT = default;

  status(const status&) NANO_NOEXCEPT = default;
  status(status&&) NANO_NOEXCEPT = default;

  status& operator=(const status&) NANO_NOEXCEPT = default;
  status& operator=(status&&) NANO_NOEXCEPT = default;

  ///
  NANO_NODC_INLINE_CXPR explicit operator bool() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE_CXPR bool operator==(status_code c) const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE_CXPR bool operator!=(status_code c) const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE_CXPR bool is_informational() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE_CXPR bool is_success() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE_CXPR bool is_redirection() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE_CXPR bool is_client_error() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE_CXPR bool is_server_error() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE_CXPR bool is_error() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE_CXPR const char* message() const NANO_NOEXCEPT;

  status_code code = status_code::invalid;

  template <class charT, class traits>
  NANO_INLINE friend std::basic_ostream<charT, traits>& operator<<(
      std::basic_ostream<charT, traits>& stream, const http::status& s);
};

/// @struct error
struct error {

  error() NANO_NOEXCEPT = default;

  NANO_INLINE_CXPR error(error_code c) NANO_NOEXCEPT;

  ~error() NANO_NOEXCEPT = default;

  error(const error&) NANO_NOEXCEPT = default;
  error(error&&) NANO_NOEXCEPT = default;

  error& operator=(const error&) NANO_NOEXCEPT = default;
  error& operator=(error&&) NANO_NOEXCEPT = default;

  /// Returns true on error.
  NANO_NODC_INLINE_CXPR explicit operator bool() const NANO_NOEXCEPT;

  NANO_NODC_INLINE_CXPR bool operator==(error c) const NANO_NOEXCEPT;

  NANO_NODC_INLINE_CXPR bool operator!=(error c) const NANO_NOEXCEPT;

  NANO_NODC_INLINE_CXPR bool valid() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE_CXPR const char* message() const NANO_NOEXCEPT;

  error_code code = error_code::none;

  template <class charT, class traits>
  NANO_INLINE friend std::basic_ostream<charT, traits>& operator<<(
      std::basic_ostream<charT, traits>& stream, const http::error& e);
};

/// @class url
class url {
public:
  static constexpr const char* kHttpScheme = "http://";
  static constexpr const char* kHttpsScheme = "https://";

  NANO_INLINE url(const char* uri);
  NANO_INLINE url(std::string_view uri);
  NANO_INLINE url(std::string&& uri) NANO_NOEXCEPT;
  NANO_INLINE url(const std::string& uri);

  // MARK: URL

  NANO_NODC_INLINE std::string get_string(bool withScheme, bool withParameters) const;

  NANO_NODC_INLINE std::string_view get_string(bool withScheme) const;

  /// Returns the domain uri.
  /// This 'https://www.abc.com/info' would return 'www.abc.com'.
  NANO_NODC_INLINE std::string_view get_domain() const;

  /// Returns the uri route.
  /// This 'https://www.abc.com/info' would return '/info'.
  NANO_NODC_INLINE std::string_view get_route() const;

  /// Returns the uri route.
  /// This 'https://www.abc.com/info' would return '/info'.
  NANO_NODC_INLINE std::string get_route(bool withParameters) const;

  // MARK: Scheme

  NANO_NODC_INLINE bool has_scheme() const NANO_NOEXCEPT;

  /// Get the uri scheme.
  /// This 'https://www.abc.com/info' would return 'https://'.
  NANO_NODC_INLINE std::string_view get_scheme() const NANO_NOEXCEPT;

  NANO_INLINE url& with_scheme(scheme sc);

  NANO_INLINE void set_scheme(scheme sc);

  NANO_NODC_INLINE bool is_http() const NANO_NOEXCEPT;

  NANO_NODC_INLINE bool is_https() const NANO_NOEXCEPT;

  // MARK: Parameters

  NANO_INLINE url& with_parameter(parameter&& param);
  NANO_INLINE url& with_parameter(const parameter& param);

  NANO_INLINE void add_parameter(parameter&& param, bool allowDuplicates = true);
  NANO_INLINE void add_parameter(const parameter& param, bool allowDuplicates = true);

  NANO_NODC_INLINE bool has_parameters() const NANO_NOEXCEPT;

  NANO_NODC_INLINE std::size_t parameter_count() const NANO_NOEXCEPT;

  NANO_NODC_INLINE bool has_parameter(std::string_view name) const NANO_NOEXCEPT;

  NANO_INLINE bool remove_parameter(std::string_view name);

  NANO_NODC_INLINE const parameter* get_parameter(std::string_view name) const NANO_NOEXCEPT;

  NANO_NODC_INLINE std::string get_parameters_string() const;

  NANO_NODC_INLINE std::vector<parameter>& get_parameters() NANO_NOEXCEPT;
  NANO_NODC_INLINE const std::vector<parameter>& get_parameters() const NANO_NOEXCEPT;

  template <class charT, class traits>
  NANO_INLINE friend std::basic_ostream<charT, traits>& operator<<(
      std::basic_ostream<charT, traits>& stream, const http::url& u);

private:
  std::string m_uri;
  std::vector<parameter> m_parameters;

  static NANO_INLINE std::size_t find_end_of_scheme(std::string_view uri);
};

/// @class response
class response {
public:
  response() = default;
  response(const response&) = default;
  response(response&&) = default;

  NANO_INLINE response(error_code err);

  NANO_INLINE response(int statusCode, error_code err);

  NANO_INLINE response(std::vector<char>&& data, int statusCode, error_code err);

  NANO_INLINE response(const std::vector<char>& data, int statusCode, error_code err);

  NANO_INLINE response(const std::vector<char>& data, int statusCode, std::vector<header_field>&& headers);

  ~response() = default;

  response& operator=(const response&) = default;
  response& operator=(response&&) = default;

  ///
  NANO_NODC_INLINE status status() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE error error() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE bool valid() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE explicit operator bool() const NANO_NOEXCEPT;

  // MARK: Data

  ///
  NANO_NODC_INLINE bool has_data() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE std::vector<char>& data() NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE const std::vector<char>& data() const NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE std::string_view as_string() const NANO_NOEXCEPT;

  NANO_NODC_INLINE bool has_header(std::string_view name) const NANO_NOEXCEPT;
  NANO_NODC_INLINE const header_field* get_header(std::string_view name) const NANO_NOEXCEPT;

  NANO_NODC_INLINE const std::string_view get_header_value(std::string_view name) const NANO_NOEXCEPT;
  ///
  NANO_NODC_INLINE const std::vector<header_field>& get_headers() const NANO_NOEXCEPT;

private:
  std::vector<char> m_data;
  struct status m_status;
  struct error m_error;
  std::vector<header_field> m_headers;
};

/// @class request
class request {
public:
  NANO_INLINE request(const http::url& u);

  // MARK: URL

  NANO_INLINE request& with_url(http::url&& u);

  NANO_INLINE request& with_url(const http::url& u);

  NANO_INLINE void set_url(http::url&& u);

  NANO_INLINE void set_url(const http::url& u);

  NANO_NODC_INLINE http::url& get_url() NANO_NOEXCEPT;

  NANO_NODC_INLINE const http::url& get_url() const NANO_NOEXCEPT;

  NANO_NODC_INLINE std::string get_url(bool withScheme, bool withParameters) const;

  NANO_NODC_INLINE std::string_view get_url(bool withScheme) const;

  // MARK: Method

  ///
  NANO_INLINE request& with_method(method m) NANO_NOEXCEPT;

  ///
  NANO_INLINE void set_method(method m) NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE method get_method() const NANO_NOEXCEPT;

  // MARK: Header

  ///
  NANO_INLINE request& with_header(header_field&& field);
  ///
  NANO_INLINE request& with_header(const header_field& field);
  ///
  NANO_INLINE void add_header(header_field&& field);

  ///
  NANO_INLINE void add_header(const header_field& field);

  ///
  NANO_NODC_INLINE bool has_headers() const NANO_NOEXCEPT;

  NANO_NODC_INLINE bool has_header(std::string_view name) const NANO_NOEXCEPT;

  NANO_INLINE bool remove_header(std::string_view name);

  NANO_NODC_INLINE const header_field* get_header(std::string_view name) const NANO_NOEXCEPT;
  ///
  NANO_NODC_INLINE std::vector<header_field>& get_headers() NANO_NOEXCEPT;

  ///
  NANO_NODC_INLINE const std::vector<header_field>& get_headers() const NANO_NOEXCEPT;

  /// Returns the domain uri.
  /// This 'https://www.abc.com/info' would return 'www.abc.com'.
  NANO_NODC_INLINE std::string_view get_domain() const;

  /// Returns the uri route.
  /// This 'https://www.abc.com/info' would return '/info'.
  NANO_NODC_INLINE std::string_view get_route() const;

  /// Returns the uri route.
  /// This 'https://www.abc.com/info' would return '/info'.
  NANO_NODC_INLINE std::string get_route(bool withParameters) const;

  // MARK: Scheme

  NANO_NODC_INLINE bool has_scheme() const NANO_NOEXCEPT;

  /// Get the uri scheme.
  /// This 'https://www.abc.com/info' would return 'https://'.
  NANO_NODC_INLINE std::string_view get_scheme() const NANO_NOEXCEPT;

  NANO_INLINE request& with_scheme(scheme sc);

  NANO_INLINE void set_scheme(scheme sc);

  NANO_NODC_INLINE bool is_http() const NANO_NOEXCEPT;

  NANO_NODC_INLINE bool is_https() const NANO_NOEXCEPT;

  // MARK: Parameters

  NANO_INLINE request& with_parameter(parameter&& param);
  NANO_INLINE request& with_parameter(const parameter& param);

  NANO_INLINE void add_parameter(parameter&& param, bool allowDuplicates = true);

  NANO_INLINE void add_parameter(const parameter& param, bool allowDuplicates = true);

  NANO_NODC_INLINE bool has_parameters() const NANO_NOEXCEPT;

  NANO_NODC_INLINE std::size_t parameter_count() const NANO_NOEXCEPT;

  NANO_NODC_INLINE bool has_parameter(std::string_view name) const NANO_NOEXCEPT;

  NANO_INLINE bool remove_parameter(std::string_view name);

  NANO_NODC_INLINE const parameter* get_parameter(std::string_view name) const NANO_NOEXCEPT;

  NANO_NODC_INLINE std::string get_parameters_string() const;

  NANO_NODC_INLINE std::vector<parameter>& get_parameters() NANO_NOEXCEPT;

  NANO_NODC_INLINE const std::vector<parameter>& get_parameters() const NANO_NOEXCEPT;

private:
  http::url m_url;
  method m_method = method::get;
  std::vector<header_field> m_headers;
};

//
// MARK: status
//

NANO_CXPR status::status(int status) NANO_NOEXCEPT : code(static_cast<status_code>(status)) {}

NANO_CXPR status::status(status_code c) NANO_NOEXCEPT : code(c) {}

NANO_CXPR status::operator bool() const NANO_NOEXCEPT { return !is_error(); }

///
NANO_CXPR bool status::operator==(status_code c) const NANO_NOEXCEPT { return code == c; }

///
NANO_CXPR bool status::operator!=(status_code c) const NANO_NOEXCEPT { return code != c; }

NANO_CXPR bool status::is_informational() const NANO_NOEXCEPT {
  return code >= status_code::continued && code < status_code::ok;
}

NANO_CXPR bool status::is_success() const NANO_NOEXCEPT {
  return code >= status_code::ok && code < status_code::multiple_choices;
}

NANO_CXPR bool status::is_redirection() const NANO_NOEXCEPT {
  return code >= status_code::multiple_choices && code < status_code::bad_request;
}

NANO_CXPR bool status::is_client_error() const NANO_NOEXCEPT {
  return code >= status_code::bad_request && code < status_code::internal_server_error;
}

NANO_CXPR bool status::is_server_error() const NANO_NOEXCEPT { return code >= status_code::internal_server_error; }

NANO_CXPR bool status::is_error() const NANO_NOEXCEPT {
  return code >= status_code::bad_request || code == status_code::invalid;
}

NANO_CXPR const char* status::message() const NANO_NOEXCEPT {
  // clang-format off
   switch (code) {
   case status_code::invalid: return "Invalid status code";

   // Informational.
   case status_code::continued: return "Continue";
   case status_code::switching_protocols: return "Switching protocols";
   case status_code::processing: return "Processing";
   case status_code::early_hints: return "Early hints";

   // Success.
   case status_code::ok: return "OK";
   case status_code::created: return "Created";
   case status_code::accepted: return "Accepted";
   case status_code::non_authoritative_information: return "Non-Authoritative information";
   case status_code::no_content: return "No content";
   case status_code::reset_content: return "Reset content";
   case status_code::partial_content: return "Partial content";
   case status_code::multi_status: return "Multi-Status";
   case status_code::already_reported: return "Already reported";
   case status_code::im_used: return "IM used";

   // Redirection.
   case status_code::multiple_choices: return "Multiple choices";
   case status_code::moved_permanently: return "Moved permanently";
   case status_code::found: return "Found";
   case status_code::see_other: return "See other";
   case status_code::not_modified: return "Not modified";
   case status_code::use_proxy: return "Use proxy";
   case status_code::temporary_redirect: return "Temporary redirect";
   case status_code::permanent_redirect: return "Permanent redirect";

   // Client errors.
   case status_code::bad_request: return "Bad request";
   case status_code::unauthorized: return "Unauthorized";
   case status_code::payment_required: return "Payment required";
   case status_code::forbidden: return "Forbidden";
   case status_code::not_found: return "Not found";
   case status_code::method_not_allowed: return "Method not allowed";
   case status_code::not_acceptable: return "Not acceptable";
   case status_code::proxy_authentication_required: return "Proxy authentication required";
   case status_code::request_timeout: return "Request timeout";
   case status_code::conflict: return "Conflict";
   case status_code::gone: return "Gone";
   case status_code::length_required: return "Length required";
   case status_code::precondition_failed: return "Precondition failed";
   case status_code::payload_too_large: return "Payload too large";
   case status_code::uri_too_long: return "URI too long";
   case status_code::unsupported_media_type: return "Unsupported media type";
   case status_code::range_not_satisfiable: return "Range not satisfiable";
   case status_code::expectation_failed: return "Expectation failed";
   case status_code::im_a_teapot: return "I'm a teapot";
   case status_code::misdirected_request: return "Misdirected request";
   case status_code::unprocessable_entity: return "Unprocessable entity";
   case status_code::locked: return "Locked";
   case status_code::failed_dependency: return "Failed dependency";
   case status_code::too_early: return "Too early";
   case status_code::upgrade_required: return "Upgrade required";
   case status_code::precondition_required: return "Precondition required";
   case status_code::too_many_requests: return "Too many requests";
   case status_code::request_header_fields_too_large: return "Request header fields too large";
   case status_code::unavailable_for_legal_reasons: return "Unavailable for legal reasons";

   // Server errors.
   case status_code::internal_server_error: return "Internal server error";
   case status_code::not_implemented: return "Not implemented";
   case status_code::bad_gateway: return "Bad gateway";
   case status_code::service_unavailable: return "Service unavailable";
   case status_code::gateway_timeout: return "Gateway timeout";
   case status_code::http_version_not_supported: return "HTTP version not supported";
   case status_code::variant_also_negotiates: return "Variant also negotiates";
   case status_code::insufficient_storage: return "Insufficient storage";
   case status_code::loop_detected: return "Loop detected";
   case status_code::not_extended: return "Not extended";
   case status_code::network_authentication_required: return "Network authentication required";
   }
  // clang-format on
}

template <class charT, class traits>
std::basic_ostream<charT, traits>& operator<<(std::basic_ostream<charT, traits>& stream, const http::status& s) {
  return stream << s.message();
}

//
// MARK: error
//

NANO_CXPR error::error(error_code c) NANO_NOEXCEPT : code(c) {}

/// Returns true on error.
NANO_CXPR error::operator bool() const NANO_NOEXCEPT { return code != error_code::none; }

NANO_CXPR bool error::operator==(error c) const NANO_NOEXCEPT { return code == c.code; }

NANO_CXPR bool error::operator!=(error c) const NANO_NOEXCEPT { return code != c.code; }

NANO_CXPR bool error::valid() const NANO_NOEXCEPT { return code == error_code::none; }

NANO_CXPR const char* error::message() const NANO_NOEXCEPT {
  // clang-format off
   switch (code) {
       case error_code::none: return "none";
       case error_code::unknown: return "unknown";
       case error_code::cancelled: return "cancelled";
       case error_code::bad_url: return "badurl";
       case error_code::timed_out: return "timedout";
       case error_code::unsupported_url: return "unsupported url";
       case error_code::cannot_find_host: return "cannot find host";
       case error_code::cannot_connect_to_host: return "cannot connect to host";
       case error_code::network_connection_lost: return "network connection lost";
       case error_code::dns_lookup_failed: return "dns lookup failed";
       case error_code::http_too_many_redirects: return "http too many redirects";
       case error_code::resource_unavailable: return "resource unavailable";
       case error_code::not_connected_to_internet: return "not connected to internet";
       case error_code::redirect_to_non_existent_location: return "redirect to non-existent location";
       case error_code::bad_server_response: return "bad server response";
       case error_code::user_cancelled_authentication: return "user cancelled authentication";
       case error_code::user_authentication_required: return "user authentication required";
       case error_code::zero_byte_resource: return "zero byte resource";
       case error_code::cannot_decode_raw_data: return "cannot decode raw data";
       case error_code::cannot_decode_content_data: return "cannot decode content data";
       case error_code::cannot_parse_response: return "cannot parse response";
       case error_code::app_transport_security_requires_secure_connection: return "app transport security requires secure connection";
       case error_code::file_does_not_exist: return "file does not exist";
       case error_code::file_is_directory: return "file is directory";
       case error_code::no_permissions_to_read_file: return "no permissions to read file";
       case error_code::data_length_exceeds_maximum: return "data length exceeds maximum";
       case error_code::file_outside_safe_area: return "file outside safe area";
       case error_code::secure_connection_failed: return "secure connection failed";
       case error_code::server_certificate_has_bad_date: return "server certificate has bad date";
       case error_code::server_certificate_untrusted: return "server certificate untrusted";
       case error_code::server_certificate_has_unknown_root: return "server certificate has unknown root";
       case error_code::server_certificate_not_yet_valid: return "server certificate not yet valid";
       case error_code::client_certificate_rejected: return "client certificate rejected";
       case error_code::client_certificate_required: return "client certificate required";
       case error_code::cannot_load_from_network: return "cannot load from network";
   }
  // clang-format on
}

template <class charT, class traits>
std::basic_ostream<charT, traits>& operator<<(std::basic_ostream<charT, traits>& stream, const http::error& e) {
  return stream << e.message();
}

//
// MARK: url
//

url::url(const char* uri)
    : m_uri(uri) {}

url::url(std::string_view uri)
    : m_uri(uri) {}

url::url(std::string&& uri) NANO_NOEXCEPT : m_uri(std::move(uri)) {}

url::url(const std::string& uri)
    : m_uri(uri) {}

std::string url::get_string(bool withScheme, bool withParameters) const {
  std::string u = withScheme ? m_uri : m_uri.substr(get_scheme().size());

  if (withParameters) {
    return u + get_parameters_string();
  }

  return u;
}

std::string_view url::get_string(bool withScheme) const {
  return withScheme ? m_uri : std::string_view(m_uri).substr(get_scheme().size());
}

std::string_view url::get_domain() const {
  std::string_view domain = get_string(false);

  std::string_view::size_type pos = domain.find_first_of('/');
  if (pos == std::string_view::npos) {
    return domain;
  }

  return domain.substr(0, pos);
}

std::string_view url::get_route() const {
  std::string_view u = std::string_view(m_uri).substr(get_scheme().size());
  std::string_view::size_type pos = u.find_first_of('/');
  return pos == std::string_view::npos ? std::string_view() : u.substr(pos);
}

std::string url::get_route(bool withParameters) const {
  return withParameters ? std::string(get_route()) + get_parameters_string() : std::string(get_route());
}

bool url::has_scheme() const NANO_NOEXCEPT { return find_end_of_scheme(m_uri) != 0; }

/// Get the uri scheme.
/// This 'https://www.abc.com/info' would return 'https://'.
std::string_view url::get_scheme() const NANO_NOEXCEPT {
  return std::string_view(m_uri).substr(0, find_end_of_scheme(m_uri));
}

url& url::with_scheme(scheme sc) {
  set_scheme(sc);
  return *this;
}

void url::set_scheme(scheme sc) {
  m_uri = (sc == scheme::http ? kHttpScheme : kHttpsScheme) + get_string(false, false);
}

bool url::is_http() const NANO_NOEXCEPT { return m_uri.find(kHttpScheme) == 0; }

bool url::is_https() const NANO_NOEXCEPT { return m_uri.find(kHttpsScheme) == 0; }

url& url::with_parameter(parameter&& param) {
  m_parameters.push_back(std::move(param));
  return *this;
}

url& url::with_parameter(const parameter& param) {
  m_parameters.push_back(param);
  return *this;
}

void url::add_parameter(parameter&& param, bool allowDuplicates) {

  if (allowDuplicates) {
    m_parameters.push_back(std::move(param));
    return;
  }

  for (parameter& p : m_parameters) {
    if (p.name == param.name) {
      p = std::move(param);
      return;
    }
  }

  m_parameters.push_back(std::move(param));
}

void url::add_parameter(const parameter& param, bool allowDuplicates) {
  if (allowDuplicates) {
    m_parameters.push_back(param);
    return;
  }

  for (parameter& p : m_parameters) {
    if (p.name == param.name) {
      p = param;
      return;
    }
  }

  m_parameters.push_back(param);
}

bool url::has_parameters() const NANO_NOEXCEPT { return !m_parameters.empty(); }

std::size_t url::parameter_count() const NANO_NOEXCEPT { return m_parameters.size(); }

bool url::has_parameter(std::string_view name) const NANO_NOEXCEPT {
  for (const parameter& p : m_parameters) {
    if (p.name == name) {
      return true;
    }
  }

  return false;
}

bool url::remove_parameter(std::string_view name) {
  for (std::size_t i = 0; i < m_parameters.size(); i++) {
    if (m_parameters[i].name == name) {
      m_parameters.erase(m_parameters.begin() + static_cast<std::vector<parameter>::difference_type>(i));
      return true;
    }
  }

  return false;
}

const parameter* url::get_parameter(std::string_view name) const NANO_NOEXCEPT {
  for (const parameter& p : m_parameters) {
    if (p.name == name) {
      return &p;
    }
  }

  return nullptr;
}

std::string url::get_parameters_string() const {
  if (m_parameters.empty()) {
    return "";
  }

  std::size_t reserve_length = 0;
  for (const parameter& p : m_parameters) {
    reserve_length += p.name.size() + p.value.size() + 2;
  }

  std::string params;
  params.reserve(reserve_length);
  params.push_back('?');
  params.append(m_parameters[0].name);
  params.push_back('=');
  params.append(m_parameters[0].value);

  for (std::size_t i = 1; i < m_parameters.size(); i++) {
    params.push_back('&');
    params.append(m_parameters[i].name);
    params.push_back('=');
    params.append(m_parameters[i].value);
  }

  return params;
}

std::vector<parameter>& url::get_parameters() NANO_NOEXCEPT { return m_parameters; }

const std::vector<parameter>& url::get_parameters() const NANO_NOEXCEPT { return m_parameters; }

std::size_t url::find_end_of_scheme(std::string_view uri) {
  std::size_t i = 0;

  while (std::isalnum(static_cast<int>(uri[i])) || uri[i] == '+' || uri[i] == '-' || uri[i] == '.') {
    i++;
  }

  const std::string_view key = "://";
  return ((uri).substr(i).substr(0, key.size()) == key) ? i + 3 : 0;
}

template <class charT, class traits>
std::basic_ostream<charT, traits>& operator<<(std::basic_ostream<charT, traits>& stream, const http::url& u) {
  return stream << u.get_string(true, true);
}

//
//
//
response::response(error_code err)
    : m_error(err) {}

response::response(int statusCode, error_code err)
    : m_status(statusCode)
    , m_error(err) {}

response::response(std::vector<char>&& data, int statusCode, error_code err)
    : m_data(std::move(data))
    , m_status(statusCode)
    , m_error(err) {}

response::response(const std::vector<char>& data, int statusCode, error_code err)
    : m_data(data)
    , m_status(statusCode)
    , m_error(err) {}

response::response(const std::vector<char>& data, int statusCode, std::vector<header_field>&& headers)
    : m_data(data)
    , m_status(statusCode)
    , m_error(error_code::none)
    , m_headers(std::move(headers)) {}

status response::status() const NANO_NOEXCEPT { return m_status; }

error response::error() const NANO_NOEXCEPT { return m_error; }

bool response::valid() const NANO_NOEXCEPT { return m_error.valid(); }

response::operator bool() const NANO_NOEXCEPT { return valid(); }

bool response::has_data() const NANO_NOEXCEPT { return !m_data.empty(); }

std::vector<char>& response::data() NANO_NOEXCEPT { return m_data; }

const std::vector<char>& response::data() const NANO_NOEXCEPT { return m_data; }

std::string_view response::as_string() const NANO_NOEXCEPT { return std::string_view(m_data.data(), m_data.size()); }

bool response::has_header(std::string_view name) const NANO_NOEXCEPT {
  for (const header_field& h : m_headers) {
    if (h.name == name) {
      return true;
    }
  }

  return false;
}

const header_field* response::get_header(std::string_view name) const NANO_NOEXCEPT {
  for (const header_field& h : m_headers) {
    if (h.name == name) {
      return &h;
    }
  }

  return nullptr;
}

const std::string_view response::get_header_value(std::string_view name) const NANO_NOEXCEPT {
  for (const header_field& h : m_headers) {
    if (h.name == name) {
      return h.value;
    }
  }

  return std::string_view();
}

const std::vector<header_field>& response::get_headers() const NANO_NOEXCEPT { return m_headers; }

//
//
//
request::request(const http::url& u)
    : m_url(u) {}

request& request::with_url(http::url&& u) {
  m_url = std::move(u);
  return *this;
}

request& request::with_url(const http::url& u) {
  m_url = u;
  return *this;
}

void request::set_url(http::url&& u) { m_url = std::move(u); }

void request::set_url(const http::url& u) { m_url = u; }

http::url& request::get_url() NANO_NOEXCEPT { return m_url; }

const http::url& request::get_url() const NANO_NOEXCEPT { return m_url; }

std::string request::get_url(bool withScheme, bool withParameters) const {
  return m_url.get_string(withScheme, withParameters);
}

std::string_view request::get_url(bool withScheme) const { return m_url.get_string(withScheme); }

request& request::with_method(method m) NANO_NOEXCEPT {
  m_method = m;
  return *this;
}

void request::set_method(method m) NANO_NOEXCEPT { m_method = m; }

method request::get_method() const NANO_NOEXCEPT { return m_method; }

request& request::with_header(header_field&& field) {
  m_headers.push_back(std::move(field));
  return *this;
}

request& request::with_header(const header_field& field) {
  m_headers.push_back(field);
  return *this;
}

void request::add_header(header_field&& field) { m_headers.push_back(std::move(field)); }

void request::add_header(const header_field& field) { m_headers.push_back(field); }

bool request::has_headers() const NANO_NOEXCEPT { return !m_headers.empty(); }

bool request::has_header(std::string_view name) const NANO_NOEXCEPT {
  for (const header_field& h : m_headers) {
    if (h.name == name) {
      return true;
    }
  }

  return false;
}

bool request::remove_header(std::string_view name) {
  for (std::size_t i = 0; i < m_headers.size(); i++) {
    if (m_headers[i].name == name) {
      m_headers.erase(m_headers.begin() + static_cast<std::vector<header_field>::difference_type>(i));
      return true;
    }
  }

  return false;
}

const header_field* request::get_header(std::string_view name) const NANO_NOEXCEPT {
  for (const header_field& h : m_headers) {
    if (h.name == name) {
      return &h;
    }
  }

  return nullptr;
}

std::vector<header_field>& request::get_headers() NANO_NOEXCEPT { return m_headers; }

const std::vector<header_field>& request::get_headers() const NANO_NOEXCEPT { return m_headers; }

std::string_view request::get_domain() const { return m_url.get_domain(); }

std::string_view request::get_route() const { return m_url.get_route(); }

std::string request::get_route(bool withParameters) const { return m_url.get_route(withParameters); }

bool request::has_scheme() const NANO_NOEXCEPT { return m_url.has_scheme(); }

std::string_view request::get_scheme() const NANO_NOEXCEPT { return m_url.get_scheme(); }

request& request::with_scheme(scheme sc) {
  m_url.set_scheme(sc);
  return *this;
}

void request::set_scheme(scheme sc) { m_url.set_scheme(sc); }

bool request::is_http() const NANO_NOEXCEPT { return m_url.is_http(); }

bool request::is_https() const NANO_NOEXCEPT { return m_url.is_https(); }

request& request::with_parameter(parameter&& param) {
  m_url.add_parameter(std::move(param));
  return *this;
}

request& request::with_parameter(const parameter& param) {
  m_url.add_parameter(param);
  return *this;
}

void request::add_parameter(parameter&& param, bool allowDuplicates) {
  m_url.add_parameter(std::move(param), allowDuplicates);
}

void request::add_parameter(const parameter& param, bool allowDuplicates) {
  m_url.add_parameter(param, allowDuplicates);
}

bool request::has_parameters() const NANO_NOEXCEPT { return m_url.has_parameters(); }

std::size_t request::parameter_count() const NANO_NOEXCEPT { return m_url.parameter_count(); }

bool request::has_parameter(std::string_view name) const NANO_NOEXCEPT { return m_url.has_parameter(name); }

bool request::remove_parameter(std::string_view name) { return m_url.remove_parameter(name); }

const parameter* request::get_parameter(std::string_view name) const NANO_NOEXCEPT { return m_url.get_parameter(name); }

std::string request::get_parameters_string() const { return m_url.get_parameters_string(); }

std::vector<parameter>& request::get_parameters() NANO_NOEXCEPT { return m_url.get_parameters(); }

const std::vector<parameter>& request::get_parameters() const NANO_NOEXCEPT { return m_url.get_parameters(); }

} // namespace nano::http.

NANO_CLANG_DIAGNOSTIC_POP()

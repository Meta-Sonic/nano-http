#include <nano/test.h>
#include <nano/http.h>

namespace {
namespace http = nano::http;

TEST_CASE("nano.http", Http, "http") {

  // Https protocol.
  {
    http::request request("https://www.synchroarts.com");

    // Scheme.
    EXPECT_TRUE(request.has_scheme());
    EXPECT_TRUE(request.get_scheme() == "https://");
    EXPECT_TRUE(request.is_https());
    EXPECT_FALSE(request.is_http());
    //
    //      // Url.
    EXPECT_TRUE(request.get_domain() == "www.synchroarts.com");
    EXPECT_TRUE(request.get_route(false) == "");
    EXPECT_TRUE(request.get_url(false, false) == "www.synchroarts.com");
    EXPECT_TRUE(request.get_url(false, true) == "www.synchroarts.com");
    EXPECT_TRUE(request.get_url(true, false) == "https://www.synchroarts.com");
    EXPECT_TRUE(request.get_url(true, true) == "https://www.synchroarts.com");
  }

  // Http protocol.
  {
    http::request request("http://www.synchroarts.com");

    // Scheme.
    EXPECT_TRUE(request.has_scheme());
    EXPECT_TRUE(request.get_scheme() == "http://");
    EXPECT_FALSE(request.is_https());
    EXPECT_TRUE(request.is_http());

    // Url.
    EXPECT_TRUE(request.get_domain() == "www.synchroarts.com");
    EXPECT_TRUE(request.get_route(false) == "");
    EXPECT_TRUE(request.get_url(false, false) == "www.synchroarts.com");
    EXPECT_TRUE(request.get_url(false, true) == "www.synchroarts.com");
    EXPECT_TRUE(request.get_url(true, false) == "http://www.synchroarts.com");
    EXPECT_TRUE(request.get_url(true, true) == "http://www.synchroarts.com");
  }
}

TEST_CASE("nano.http", Scheme, "http") {
  // Without scheme.
  {
    http::request request("www.synchroarts.com");

    // Scheme.
    EXPECT_FALSE(request.has_scheme());
    EXPECT_FALSE(request.get_scheme() == "https://");
    EXPECT_FALSE(request.is_https());
    EXPECT_FALSE(request.is_http());

    // Url.
    EXPECT_TRUE(request.get_domain() == "www.synchroarts.com");
    EXPECT_TRUE(request.get_route(false) == "");
    EXPECT_TRUE(request.get_url(false, false) == "www.synchroarts.com");
    EXPECT_TRUE(request.get_url(false, true) == "www.synchroarts.com");
    EXPECT_TRUE(request.get_url(true, false) == "www.synchroarts.com");
    EXPECT_TRUE(request.get_url(true, true) == "www.synchroarts.com");
  }

  // With added scheme.
  {
    http::request request = http::request("www.synchroarts.com").with_scheme(http::scheme::https);

    // Scheme.
    EXPECT_TRUE(request.has_scheme());
    EXPECT_TRUE(request.get_scheme() == "https://");
    EXPECT_TRUE(request.is_https());
    EXPECT_FALSE(request.is_http());

    // Url.
    EXPECT_TRUE(request.get_domain() == "www.synchroarts.com");
    EXPECT_TRUE(request.get_route(false) == "");
    EXPECT_TRUE(request.get_url(false, false) == "www.synchroarts.com");
    EXPECT_TRUE(request.get_url(false, true) == "www.synchroarts.com");
    EXPECT_TRUE(request.get_url(true, false) == "https://www.synchroarts.com");
    EXPECT_TRUE(request.get_url(true, true) == "https://www.synchroarts.com");
  }
}

TEST_CASE("nano.http", Route, "http") {
  http::request request("https://www.synchroarts.com/upgrade-info");

  // Scheme.
  EXPECT_TRUE(request.has_scheme());
  EXPECT_TRUE(request.get_scheme() == "https://");
  EXPECT_TRUE(request.is_https());
  EXPECT_FALSE(request.is_http());

  // Url.
  EXPECT_TRUE(request.get_domain() == "www.synchroarts.com");
  EXPECT_TRUE(request.get_route(false) == "/upgrade-info");
  EXPECT_TRUE(request.get_url(false, false) == "www.synchroarts.com/upgrade-info");
  EXPECT_TRUE(request.get_url(false, true) == "www.synchroarts.com/upgrade-info");
  EXPECT_TRUE(request.get_url(true, false) == "https://www.synchroarts.com/upgrade-info");
  EXPECT_TRUE(request.get_url(true, true) == "https://www.synchroarts.com/upgrade-info");
}

TEST_CASE("nano.http", Parameters, "http") {
  http::request request = http::request("https://www.synchroarts.com/upgrade-info")
                              .with_parameter({ "p", "RVPRO4" })
                              .with_parameter({ "os", "mac" })
                              .with_parameter({ "v", "4.4.1.5" });

  // Scheme.
  EXPECT_TRUE(request.has_scheme());
  EXPECT_TRUE(request.get_scheme() == "https://");
  EXPECT_TRUE(request.is_https());
  EXPECT_FALSE(request.is_http());

  // Url.
  EXPECT_TRUE(request.get_domain() == "www.synchroarts.com");
  EXPECT_TRUE(request.get_route(false) == "/upgrade-info");
  EXPECT_TRUE(request.get_route(true) == "/upgrade-info?p=RVPRO4&os=mac&v=4.4.1.5");
  EXPECT_TRUE(request.get_url(false, false) == "www.synchroarts.com/upgrade-info");
  EXPECT_TRUE(request.get_url(false, true) == "www.synchroarts.com/upgrade-info?p=RVPRO4&os=mac&v=4.4.1.5");
  EXPECT_TRUE(request.get_url(true, false) == "https://www.synchroarts.com/upgrade-info");
  EXPECT_TRUE(request.get_url(true, true) == "https://www.synchroarts.com/upgrade-info?p=RVPRO4&os=mac&v=4.4.1.5");
}
} // namespace.

NANO_TEST_MAIN()

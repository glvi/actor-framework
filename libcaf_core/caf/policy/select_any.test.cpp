// This file is part of CAF, the C++ Actor Framework. See the file LICENSE in
// the main distribution directory for license terms and copyright or visit
// https://github.com/actor-framework/actor-framework/blob/master/LICENSE.

#include "caf/policy/select_any.hpp"

#include "caf/test/fixture/deterministic.hpp"
#include "caf/test/test.hpp"

#include "caf/actor_system.hpp"
#include "caf/event_based_actor.hpp"
#include "caf/log/test.hpp"
#include "caf/scoped_actor.hpp"
#include "caf/sec.hpp"

using caf::policy::select_any;

using namespace caf;

namespace {

struct fixture : test::fixture::deterministic {
  scoped_actor self{sys};

  template <class F>
  actor make_server(F f) {
    auto init = [f]() -> behavior {
      return {
        [f](int x, int y) { return f(x, y); },
      };
    };
    return sys.spawn(init);
  }

  auto make_error_handler() {
    return [](const error& err) {
      test::runnable::current().fail("unexpected error: {}", err);
    };
  }

  auto make_counting_error_handler(size_t* count) {
    return [count](const error&) { *count += 1; };
  }

  template <class... ResponseHandles>
  auto fuse(ResponseHandles&... handles) {
    return select_any<type_list<int>>{
      {handles.id()...},
      disposable::make_composite({handles.policy().pending_timeouts()...})};
  }
};

#define SUBTEST(message)                                                       \
  dispatch_messages();                                                         \
  log::test::debug("subtest: {}", message);                                    \
  for (int subtest_dummy = 0; subtest_dummy < 1; ++subtest_dummy)

WITH_FIXTURE(fixture) {

TEST("select_any picks the first arriving integer") {
  auto f = [](int x, int y) { return x + y; };
  auto server1 = make_server(f);
  auto server2 = make_server(f);
  SUBTEST("request.receive") {
    SUBTEST("single integer") {
      auto r1 = self->request(server1, infinite, 1, 2);
      auto r2 = self->request(server2, infinite, 2, 3);
      auto choose = fuse(r1, r2);
      dispatch_messages();
      choose.receive(
        self.ptr(), [this](int result) { check_eq(result, 3); },
        make_error_handler());
    }
  }
  SUBTEST("request.then") {
    int result = 0;
    auto client = sys.spawn(
      [this, server1, server2, &result](event_based_actor* client_ptr) {
        auto r1 = client_ptr->request(server1, infinite, 1, 2);
        auto r2 = client_ptr->request(server2, infinite, 2, 3);
        auto choose = fuse(r1, r2);
        choose.then(
          client_ptr, [&result](int x) { result = x; }, make_error_handler());
      });
    expect<int, int>().with(1, 2).from(client).to(server1);
    expect<int, int>().with(2, 3).from(client).to(server2);
    expect<int>().with(3).from(server1).to(client);
    expect<int>().with(5).from(server2).to(client);
    log::test::debug("request.then picks the first arriving result");
    check_eq(result, 3);
  }
  SUBTEST("request.await") {
    int result = 0;
    auto client = sys.spawn(
      [this, server1, server2, &result](event_based_actor* client_ptr) {
        auto r1 = client_ptr->request(server1, infinite, 1, 2);
        auto r2 = client_ptr->request(server2, infinite, 2, 3);
        auto choose = fuse(r1, r2);
        choose.await(
          client_ptr, [&result](int x) { result = x; }, make_error_handler());
      });
    expect<int, int>().with(1, 2).from(client).to(server1);
    expect<int, int>().with(2, 3).from(client).to(server2);
    // TODO: DSL (mailbox.peek) cannot deal with receivers that skip messages.
    // expect<int>().with(3). from(server1).to(client);
    // expect<int>().with(5). from(server2).to(client);
    dispatch_messages();
    log::test::debug(
      "request.await froces responses into reverse request order");
    check_eq(result, 5);
  }
}

TEST("select_any calls the error handler at most once") {
  auto f = [](int, int) -> result<int> { return sec::invalid_argument; };
  auto server1 = make_server(f);
  auto server2 = make_server(f);
  SUBTEST("request.receive") {
    auto r1 = self->request(server1, infinite, 1, 2);
    auto r2 = self->request(server2, infinite, 2, 3);
    auto choose = fuse(r1, r2);
    dispatch_messages();
    size_t errors = 0;
    choose.receive(
      self.ptr(),
      [this](int) { fail("fan-in policy called the result handler"); },
      make_counting_error_handler(&errors));
    check_eq(errors, 1u);
  }
  SUBTEST("request.then") {
    size_t errors = 0;
    auto client = sys.spawn(
      [this, server1, server2, &errors](event_based_actor* client_ptr) {
        auto r1 = client_ptr->request(server1, infinite, 1, 2);
        auto r2 = client_ptr->request(server2, infinite, 2, 3);
        auto choose = fuse(r1, r2);
        choose.then(
          client_ptr,
          [this](int) { fail("fan-in policy called the result handler"); },
          make_counting_error_handler(&errors));
      });
    expect<int, int>().with(1, 2).from(client).to(server1);
    expect<int, int>().with(2, 3).from(client).to(server2);
    expect<error>().with(sec::invalid_argument).from(server1).to(client);
    expect<error>().with(sec::invalid_argument).from(server2).to(client);
    check_eq(errors, 1u);
  }
  SUBTEST("request.await") {
    size_t errors = 0;
    auto client = sys.spawn(
      [this, server1, server2, &errors](event_based_actor* client_ptr) {
        auto r1 = client_ptr->request(server1, infinite, 1, 2);
        auto r2 = client_ptr->request(server2, infinite, 2, 3);
        auto choose = fuse(r1, r2);
        choose.await(
          client_ptr,
          [this](int) { fail("fan-in policy called the result handler"); },
          make_counting_error_handler(&errors));
      });
    expect<int, int>().with(1, 2).from(client).to(server1);
    expect<int, int>().with(2, 3).from(client).to(server2);
    // TODO: DSL (mailbox.peek) cannot deal with receivers that skip messages.
    // expect<int>().with(3). from(server1).to(client);
    // expect<int>().with(5). from(server2).to(client);
    dispatch_messages();
    check_eq(errors, 1u);
  }
}

} // WITH_FIXTURE(fixture)

} // namespace

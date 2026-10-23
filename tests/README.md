# Runtime integration and E2E tests

Public relay/supervisor scenarios belong in `tests/integration`; scenarios
that start real runtime containers belong in `tests/e2e`. Package-local tests
that verify unexported implementation details remain next to the code.

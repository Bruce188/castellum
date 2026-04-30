# Test Conventions

## STIX 2.1 schemas — refresh cadence

The repository ships inline OASIS STIX 2.1 JSON schemas under
`backend/src/test/resources/schemas/stix-2.1/`. This is a sandboxed-
network workaround: tests must validate generated STIX bundles without
making live HTTPS calls to `raw.githubusercontent.com`.

To refresh:

```
bash scripts/refresh-stix-schemas.sh
cd backend && ./mvnw test -Dtest=StixBundleSchemaTest
```

Run the refresh on STIX-spec point releases (~12-month cadence) or
whenever `StixBundleSchemaTest` reports a structural mismatch traced to
a spec change. Commit the refreshed schemas in the same change as the
bundle producer update; do NOT commit live-network test fixtures.

A future CI workflow should invoke the refresh and run the bundle
schema test as a single gate:

```
bash scripts/refresh-stix-schemas.sh && cd backend && ./mvnw test
```

## Slice-test imports for `@PreAuthorize` controllers

`@WebMvcTest(<Controller>.class)` does not autowire `SecurityConfig` by
default. Without it, slice tests run with method-level `@PreAuthorize`
silently disabled — every request appears authenticated. The required
imports for any slice test of a `@PreAuthorize`-protected controller
are:

```java
@Import({SecurityConfig.class, JwtAuthenticationFilter.class,
         RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
```

Plus `@MockBean` declarations for `JwtService`, `UserRepository`,
`CastellumUserDetailsService`, and the controller's service collaborator.

This idiom is load-bearing across every slice test in
`backend/src/test/java/io/castellum/web/` and
`backend/src/test/java/io/castellum/security/`. Adding a new slice test
without the four `@Import`s causes role enforcement to be silently
permissive — tests pass even when the production controller would 403.

Anonymous-401 cases inside an `@WithMockUser`-annotated class use
`SecurityMockMvcRequestPostProcessors.anonymous()` to override the
class-level `@WithMockUser` on a per-request basis:

```java
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;

@Test
void anon_returns401() throws Exception {
    mvc.perform(get("/api/devices").with(anonymous()))
        .andExpect(status().isUnauthorized());
}
```

## Maven profile `cap-net-raw-smoke`

The default `cd backend && ./mvnw test` profile does NOT run the
container-cap smoke test. To run it (CI or operator):

```
docker build -t castellum:latest .
cd backend && ./mvnw -P cap-net-raw-smoke test -Dtest=CapNetRawSmokeTest
```

The test additionally `Assumptions.abort`s when:
- `docker --version` is not available (Docker not installed).
- `docker image inspect castellum:latest` exits non-zero (image not
  built).

In either case JUnit reports the test as skipped, not failed. The
default `mvn test` profile runs without ever activating the
`castellum.cap-net-raw-smoke` system property, so `CapNetRawSmokeTest`
remains disabled (`@EnabledIfSystemProperty` evaluates to false) and is
absent from the default test count.

package io.castellum.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Forwards SPA client-side routes to the static {@code index.html} shell so deep links
 * (e.g. {@code /cves}, {@code /topology}, {@code /scans/42}) survive a browser refresh
 * instead of 404ing. The React app is built into {@code classpath:/static/} at image time.
 *
 * <p>Scope is intentionally narrow so this never shadows real endpoints or assets:
 * <ul>
 *   <li>{@code [^.]*} per segment never matches a path containing a dot, so built assets
 *       ({@code /assets/*.js}, {@code /favicon.svg}, {@code /index.html}) fall through to
 *       Spring's static {@code ResourceHttpRequestHandler}.</li>
 *   <li>The {@code (?!api$)(?!actuator$)} lookahead on the first segment keeps
 *       {@code /api/**} and {@code /actuator/**} out of the fallback.</li>
 * </ul>
 * Two segments cover every route the SPA defines, including the one nested route
 * ({@code /scans/:id}); deeper paths are intentionally not forwarded.
 */
@Controller
public class SpaForwardController {

    @GetMapping(value = {
            "/",
            "/{first:(?!api$)(?!actuator$)[^.]*}",
            "/{first:(?!api$)(?!actuator$)[^.]*}/{second:[^.]*}"
    })
    public String forward() {
        return "forward:/index.html";
    }
}

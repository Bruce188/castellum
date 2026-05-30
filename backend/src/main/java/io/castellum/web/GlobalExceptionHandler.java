package io.castellum.web;

import io.castellum.discovery.DiscoveryUnavailableException;
import io.castellum.graph.GraphTooLargeException;
import io.castellum.threatintel.ExportQueueFullException;
import io.castellum.ot.OtProbeDecodeException;
import io.castellum.ot.OtProbeNotImplementedException;
import io.castellum.ot.OtProbeTimeoutException;
import io.castellum.ot.OtProbeUnreachableException;
import io.castellum.scan.ScanScopeTooLargeException;
import io.castellum.threatintel.IntegrationProbeTimeoutException;
import io.castellum.threatintel.IntegrationProbeUnreachableException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolation(ConstraintViolationException ex) {
        log.warn("Constraint violation: {}", ex.getMessage());
        List<String> details = ex.getConstraintViolations().stream()
            .map(v -> v.getPropertyPath() + ": " + v.getMessage())
            .collect(Collectors.toList());
        return ResponseEntity.badRequest().body(Map.of("error", "Validation failed", "details", details));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleMethodArgumentNotValid(MethodArgumentNotValidException ex) {
        log.warn("Method argument not valid: {}", ex.getMessage());
        List<String> details = ex.getBindingResult().getFieldErrors().stream()
            .map(e -> e.getField() + ": " + e.getDefaultMessage())
            .collect(Collectors.toList());
        return ResponseEntity.badRequest().body(Map.of("error", "Validation failed", "details", details));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleHttpMessageNotReadable(HttpMessageNotReadableException ex) {
        log.warn("HTTP message not readable: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(Map.of("error", "Malformed request body", "details", List.of(ex.getMessage())));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
        log.warn("Illegal argument: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage(), "details", List.of()));
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<Map<String, Object>> handleNoSuchElement(NoSuchElementException ex) {
        log.warn("Resource not found: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(Map.of("error", "Not found", "details", List.of()));
    }

    @ExceptionHandler(DiscoveryUnavailableException.class)
    public ResponseEntity<Map<String, Object>> handleDiscoveryUnavailable(DiscoveryUnavailableException ex) {
        log.warn("Discovery unavailable: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
            .body(Map.of("error", "discovery_unavailable", "message", ex.getMessage()));
    }

    @ExceptionHandler(GraphTooLargeException.class)
    public ResponseEntity<Map<String, Object>> handleGraphTooLarge(GraphTooLargeException ex) {
        log.warn("Graph too large: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
            .body(Map.of("error", "GRAPH_TOO_LARGE", "message", ex.getMessage()));
    }

    @ExceptionHandler(ScanScopeTooLargeException.class)
    public ResponseEntity<Map<String, Object>> handleScanScopeTooLarge(ScanScopeTooLargeException ex) {
        log.warn("Scan scope too large: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(Map.of(
            "error", "scope_too_large",
            "message", ex.getMessage(),
            "prefix", ex.getPrefix(),
            "maxAllowedPrefix", ex.getMaxAllowedPrefix()
        ));
    }

    @ExceptionHandler(OtProbeUnreachableException.class)
    public ResponseEntity<Map<String, Object>> handleOtProbeUnreachable(OtProbeUnreachableException ex) {
        log.warn("OT probe unreachable: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
            .body(Map.of("error", "ot_probe_unreachable", "message", ex.getMessage()));
    }

    @ExceptionHandler(OtProbeTimeoutException.class)
    public ResponseEntity<Map<String, Object>> handleOtProbeTimeout(OtProbeTimeoutException ex) {
        log.warn("OT probe timeout: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT)
            .body(Map.of("error", "ot_probe_timeout", "message", ex.getMessage()));
    }

    @ExceptionHandler(OtProbeDecodeException.class)
    public ResponseEntity<Map<String, Object>> handleOtProbeDecode(OtProbeDecodeException ex) {
        log.warn("OT probe decode failure: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
            .body(Map.of("error", "ot_probe_decode_failure", "message", ex.getMessage()));
    }

    @ExceptionHandler(OtProbeNotImplementedException.class)
    public ResponseEntity<Map<String, Object>> handleOtProbeNotImplemented(OtProbeNotImplementedException ex) {
        log.warn("OT probe not implemented: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
            .body(Map.of("error", "ot_probe_not_implemented", "message", ex.getMessage()));
    }

    @ExceptionHandler(IntegrationProbeUnreachableException.class)
    public ResponseEntity<Map<String, Object>> handleIntegrationProbeUnreachable(IntegrationProbeUnreachableException ex) {
        log.warn("Integration probe unreachable: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
            .body(Map.of("error", "integration_probe_unreachable", "message", ex.getMessage()));
    }

    @ExceptionHandler(IntegrationProbeTimeoutException.class)
    public ResponseEntity<Map<String, Object>> handleIntegrationProbeTimeout(IntegrationProbeTimeoutException ex) {
        log.warn("Integration probe timeout: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT)
            .body(Map.of("error", "integration_probe_timeout", "message", ex.getMessage()));
    }

    @ExceptionHandler(ExportQueueFullException.class)
    public ResponseEntity<Map<String, Object>> handleExportQueueFull(ExportQueueFullException ex) {
        log.warn("Export queue full: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
            .body(Map.of("error", "export_queue_full", "message", ex.getMessage()));
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<Map<String, Object>> handleIoException(IOException ex) {
        log.warn("Upstream unavailable: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
            .body(Map.of("error", "upstream_unavailable", "message", ex.getMessage() != null ? ex.getMessage() : "unknown"));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentials(BadCredentialsException e, HttpServletRequest req) {
        return ResponseEntity.status(401)
            .body(Map.of("error", "unauthorized", "status", 401, "path", req.getRequestURI()));
    }

}

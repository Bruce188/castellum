package io.castellum.scan;

public record NmapResult(int exitCode, String stdout, String stderr) {}

# syntax=docker/dockerfile:1.7
ARG DISTROLESS_VARIANT=nonroot

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY backend/pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -B dependency:go-offline
COPY backend/src ./src
# Tests run separately in CI (mvn test) before image build; skip here to keep the builder lean.
RUN --mount=type=cache,target=/root/.m2 mvn -B -DskipTests package
RUN cp target/backend-*.jar /castellum.jar

FROM gcr.io/distroless/java21-debian12:${DISTROLESS_VARIANT}
COPY --from=build /castellum.jar /app/castellum.jar
# Belt-and-suspenders: distroless :nonroot defaults to UID 65532, but USER nonroot also covers callers overriding DISTROLESS_VARIANT=latest.
USER nonroot
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/castellum.jar"]

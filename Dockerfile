# syntax=docker/dockerfile:1.7
ARG DISTROLESS_VARIANT=nonroot

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY backend/pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -B dependency:go-offline
COPY backend/src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -B -DskipTests package
RUN cp target/backend-*.jar /castellum.jar

FROM gcr.io/distroless/java21-debian12:${DISTROLESS_VARIANT}
COPY --from=build /castellum.jar /app/castellum.jar
USER nonroot
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/castellum.jar"]

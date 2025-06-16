# ---------- Stage 1: Build the Java application ----------
FROM maven:3.9.6-eclipse-temurin-21 AS builder

WORKDIR /build
COPY CWTSign/pom.xml .
COPY CWTSign/src ./src

RUN mvn clean package -DskipTests

# ---------- Stage 2: Create runtime image ----------
FROM eclipse-temurin:21-jdk-alpine

WORKDIR /app

# Copy the jar from the builder stage
COPY --from=builder /build/target/*.jar app.jar

EXPOSE 8091

ENTRYPOINT ["java", "-jar", "app.jar"]

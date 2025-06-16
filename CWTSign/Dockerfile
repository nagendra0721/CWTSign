# ---------- Stage 1: Build the Java application ----------
FROM maven:3.9.6-eclipse-temurin-21 AS builder

WORKDIR /build

# Copy project files
COPY pom.xml .
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests

# ---------- Stage 2: Runtime image ----------
FROM eclipse-temurin:21-jdk-alpine

WORKDIR /app

# Copy built JAR from builder stage
COPY --from=builder /build/target/*.jar app.jar

EXPOSE 8091

ENTRYPOINT ["java", "-jar", "app.jar"]

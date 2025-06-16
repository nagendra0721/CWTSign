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

# Create the expected directory for keystore
RUN mkdir -p /Mosip

WORKDIR /app

# Copy built JAR from builder stage
COPY --from=builder /build/target/*.jar app.jar

# Expose port
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]

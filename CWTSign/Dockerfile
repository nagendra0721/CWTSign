# Use OpenJDK 21 base image from Eclipse Temurin
FROM eclipse-temurin:21-jdk-alpine

# Copy the JAR file into the container
# This expects the JAR to be named `app.jar` in the Docker build context (root)
COPY app.jar /app.jar

# Set the entrypoint to run the JAR
ENTRYPOINT ["java", "-jar", "/app.jar"]

EXPOSE 8091

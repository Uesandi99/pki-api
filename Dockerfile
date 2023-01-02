FROM maven:3.8.6-openjdk-18-slim

COPY ./ ./

RUN mvn clean package

CMD ["java", "-jar", "target/pki-api-1.jar"]
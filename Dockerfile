# Base image: Use official PlatformIO image with ESP8266 support
FROM platformio/platformio-core:latest

# Install dependencies for ESP8266 and PlatformIO
RUN platformio platform install espressif8266

# Download and install latest OakCore release into PlatformIO cores
RUN mkdir -p /root/.platformio/packages/framework-arduinoespressif8266-oakcore && \
    curl -L https://github.com/digistump/oakcore/releases/latest/download/oakcore.zip -o /tmp/oakcore.zip && \
    unzip /tmp/oakcore.zip -d /root/.platformio/packages/framework-arduinoespressif8266-oakcore && \
    rm /tmp/oakcore.zip

# Set working directory for builds
WORKDIR /project

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["platformio", "run"]

# Particle Cloud Docker Image for OakCore

This Docker image provides a PlatformIO environment configured to build Particle OakCore firmware for ESP8266 devices.

## Features

- PlatformIO core installed
- ESP8266 platform installed
- OakCore framework installed (latest release)
- Supports building sketches and libraries for Particle Oak devices
- Outputs firmware binaries and logs as per Particle specs

## Usage

Build the Docker image:

```bash
docker build -t particle-oakcore .
```

Run the container with your project mounted:

```bash
docker run --rm -v $(pwd):/project particle-oakcore
```

This will build the project in `/project` inside the container.

## Testing

To test the image, place a PlatformIO project with OakCore platform in your current directory and run the container as above. The build output will be in `.pio/build` inside your project directory.

## Notes

- The OakCore release URL in the Dockerfile may need to be updated manually when new releases occur.
- The image matches Particle's Docker specs for cloud compilation.
- For debugging, run the container interactively:

```bash
docker run -it --rm -v $(pwd):/project particle-oakcore /bin/bash
```

## Credits

Developed for Digistump LLC by Atlas 4 autonomous maintenance worker.

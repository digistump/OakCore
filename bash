   docker build -t particle-cloud-compiler .
   ```

2. Run the compiler with the example input:
   ```bash
   docker run --rm \
       -v $(pwd)/example_input:/workspace/input:ro \
       -v $(pwd)/example_output:/workspace/output \
       particle-cloud-compiler
   ```

3. Check the output:
   ```bash
   ls -la example_output/
   ```

## Troubleshooting

### Build fails with "platform not found"
Run `pio platform install particle` inside the container or rebuild the image.

### Permission denied errors
Ensure the output directory is writable by the Docker user.

### No firmware.bin generated
Check the build.log for compilation errors. Common issues include missing libraries or syntax errors in the sketch.
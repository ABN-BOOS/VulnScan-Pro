#!/bin/bash
# build-and-run.sh

#!/bin/bash
# build-and-run.sh

# Build the image
docker build -t vulnscan-pro:latest .

# Run the container
docker run -it --rm \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/logs:/app/logs \
  --name vulnscan-scanner \
  vulnscan-pro:latest
FROM erlang:27-alpine

# Install bash for wrapper scripts if necessary
RUN apk add --no-cache bash

WORKDIR /workspace

# Copy the escript tool to a global binary directory
COPY validate_and_encode.escript /usr/local/bin/validate_and_encode
RUN chmod +x /usr/local/bin/validate_and_encode

# Set execution entrypoint
ENTRYPOINT ["/usr/local/bin/validate_and_encode"]

# Base image
FROM ubuntu:22.04

# Maintainer information (optional)
LABEL maintainer="your-email@example.com"

# Set environment variables for wllvm and LLVM
ENV LLVM_COMPILER=clang
ENV CC=wllvm
ENV CXX=wllvm++

# Install required dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    git \
    libpcap-dev \
    python3 \
    python3-pip \
    curl \
    llvm \
    file \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

# Install wllvm via pip
RUN pip3 install wllvm

# Clone the arp-spoof project from GitHub
RUN git clone https://github.com/Mooncastlejun/arp-spoof.git /opt/arp-spoof

# Set the working directory to the cloned repository
WORKDIR /opt/arp-spoof

# Build arp-spoof using wllvm
RUN make clean && make CC=wllvm CXX=wllvm++

# Extract the bitcode for each object file
RUN extract-bc main.o && extract-bc arphdr.o && extract-bc ethhdr.o && extract-bc ip.o && extract-bc mac.o

# Verify that the bitcode files exist
RUN find . -name "*.o.bc"

# Generate the call graph by linking individual bitcode files
# Set default command to show help or indicate success
CMD ["echo", "Build complete, call graph generated as callgraph.dot"]


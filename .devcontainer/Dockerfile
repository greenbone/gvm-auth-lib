FROM debian:stable-slim

ARG DEBIAN_FRONTEND=noninteractive

ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash-completion \
    ca-certificates \
    clang-format \
    cmake \
    gcc \
    gdb \
    git \
    less \
    libc6-dev \
    libcgreen1-dev \
    libglib2.0-dev \
    make \
    openssh-client \
    passwd \
    pkg-config \
    rustup \
    gosu \
    sudo

# add non-root user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

RUN gosu $USERNAME rustup update stable \
    && gosu $USERNAME rustup default stable \
    && gosu $USERNAME rustup component add clippy rustfmt rust-analyzer


CMD ["/bin/bash"]

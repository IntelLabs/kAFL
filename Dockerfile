# Copyright (C) Intel Corporation, 2022
# SPDX-License-Identifier: MIT
ARG baseimage=debian:bullseye-slim
FROM ${baseimage} as build
ARG pyinstaller_version=5.7.0

WORKDIR /app
COPY . .

# skip ghidra since it adds 1G to the final image,
# and we don't use it for our fuzzing use case with Docker
RUN apt-get update && apt-get install -y --no-install-recommends build-essential git python3 python3-venv && \
    make deploy -- --tags fuzzer --skip-tags kernel,kvm_device,ghidra

# create pyinstaller stub for executable Python packages
# https://github.com/pyinstaller/pyinstaller/issues/2560
RUN printf "%s\n" 'from kafl_fuzzer.__main__ import main' \
            'from contextlib import suppress' \
            'with suppress(KeyboardInterrupt):' \
            '    main()' > ./kafl/fuzzer/stub.py
# TODO: how to make pyinstaller detect Extension modules ?
# move build/*/bitmap*.so as bitmap.so
# include it in the pyinstaller executable
RUN cd ./kafl/fuzzer && find build -name 'bitmap*.so' -exec mv {} bitmap.so \;
# compile kafl as standalone python app
RUN ./kafl/.venv/bin/pip install pyinstaller==${pyinstaller_version} && \
    cd ./kafl/fuzzer  && /app/kafl/.venv/bin/pyinstaller \
        --onefile --name kafl \
        --add-data kafl_fuzzer/common/config/default_settings.yaml:kafl_fuzzer/common/config \
        --add-data kafl_fuzzer/logging.yaml:kafl_fuzzer \
        --add-binary bitmap.so:kafl_fuzzer/native \
        stub.py

# create kafl config file
RUN printf "%s\n" 'qemu_path: /usr/local/bin/qemu-system-x86_64' \
                  'ptdump_path: /usr/local/bin/ptdump' \
                  'radamsa_path: /usr/local/bin/radamsa' \
                  'workdir: /workdir' >> settings.yaml

FROM ${baseimage} as run
# install QEMU
COPY --from=build /app/kafl/qemu/x86_64-softmmu/qemu-system-x86_64 /usr/local/bin/
COPY --from=build /app/kafl/qemu/pc-bios/* /usr/local/share/qemu-firmware/
# install radamsa
COPY --from=build /app/kafl/radamsa/bin/radamsa /usr/local/bin
# install ptdump
COPY --from=build /app/kafl/libxdc/build/ptdump /usr/local/bin
# installer fuzzer
COPY --from=build /app/kafl/fuzzer/dist/kafl /usr/local/bin
# install config file
COPY --from=build /app/settings.yaml /etc/xdg/kAFL/

# define kAFL WORKDIR volume (not to be confused with Dockerfile's WORKDIR)
VOLUME ["/workdir"]

# Setup env to run Dockerized Python app
ENV LANG C.UF-8
ENV LC_ALL C.UTF-8
# don't write .pyc compiled code
ENV PYTHONDONTWRITEBYTECODE 1
# enable python stacktraces on segfaults
ENV PYTHONFAULTHANDLER 1
# ensure that python output is sent straight to container logs without buffering
ENV PYTHONUNBUFFERED 1

ENTRYPOINT ["kafl"]

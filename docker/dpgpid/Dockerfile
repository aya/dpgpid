ARG PYTHON_RELEASE=3.10
FROM python:${PYTHON_RELEASE}-alpine as dist
LABEL maintainer aynic.os <support+docker@asycn.io>

ARG DOCKER_BUILD_DIR=.
ARG OPERATING_SYSTEM=Linux
ARG PROCESSOR_ARCHITECTURE=x86_64
ARG PYTHON_RELEASE=3.10

WORKDIR /opt/dpgpid
COPY requirements.txt ./
RUN apk add --no-cache --virtual .build-deps \
    g++ \
    libffi-dev \
    protobuf \
 && /usr/local/bin/python${PYTHON_RELEASE} -m venv ./ \
 && ./bin/pip${PYTHON_RELEASE} install -U pip wheel \
 && ./bin/pip${PYTHON_RELEASE} install -r ./requirements.txt \
 && wget https://github.com/libp2p/go-libp2p-core/raw/master/crypto/pb/crypto.proto \
 && protoc --python_out=./lib/python${PYTHON_RELEASE}/site-packages/ crypto.proto \
 && rm -rf /root/.cache ./build ./crypto.proto \
 && apk del --no-network .build-deps \
 && find ./lib -type f -executable \
     -exec scanelf --needed --nobanner --format '%n#p' '{}' ';' \
      | tr ',' '\n' \
      | sort -u \
      | awk 'system("[ -e /lib/"$1" -o -e /usr/lib/"$1" -o -e /opt/dpgpid/lib/python'"${PYTHON_RELEASE}"'/site-packages/*/"$1" ]") == 0 { next } { print "so:" $1 }' \
      | xargs -rt apk add --no-cache

RUN apk add --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing \
    envsubst \
 && apk add --no-cache \
    bash \
    ca-certificates \
    libc6-compat \
    libsodium \
    make \
    gpg \
 && OS="$(echo ${OPERATING_SYSTEM} |awk '{print tolower($0)}')"; \
    ARCH="$(echo ${PROCESSOR_ARCHITECTURE})"; \
    wget -qO - https://github.com/koalaman/shellcheck/releases/download/stable/shellcheck-stable.${OS}.${ARCH}.tar.xz |tar --strip-components 1 -C /usr/local/bin -xJf - \
 && mkdir -p /usr/local/lib/shellspec \
 && wget -qO - https://github.com/shellspec/shellspec/archive/latest.tar.gz |tar --strip-components 1 -C /usr/local/lib/shellspec -xzf - \
 && ln -s /usr/local/lib/shellspec/shellspec /usr/local/bin/shellspec

COPY --from=ipfs/go-ipfs:v0.13.0-rc1 /usr/local/bin/ipfs /usr/local/bin/
COPY README.md ./
COPY COPYING ./
COPY Makefile ./
COPY dpgpid ./bin/dpgpid
COPY gpgkey ./bin/gpgkey

ENV PATH=/opt/dpgpid/bin:$PATH

ENTRYPOINT []
CMD ["bash"]

FROM dist as master
ARG UID
ARG USER
ENV UID=${UID:-999}
ENV GID=${UID}
ENV USER=dpgpid

# If we provide a specific UID
RUN let $UID >/dev/null 2>&1 \
# Remove user with $UID if it is not our $USER
 && if [ "$(getent passwd $UID |awk 'BEGIN {FS=":"} {print $1}')" != "$USER" ]; then \
      sed -i '/^'$(getent passwd $UID |awk 'BEGIN {FS=":"} {print $1}')':x:'$UID':/d' /etc/passwd; \
      sed -i '/^'$(getent group $GID |awk 'BEGIN {FS=":"} {print $1}')':x:'$GID':/d' /etc/group; \
    fi \
# Force $UID if our $USER already exists
 && sed -i 's/^'$USER':x:[0-9]\+:[0-9]\+:/'$USER':x:'$UID':'$GID':/' /etc/passwd \
 && sed -i 's/^'$USER':x:[0-9]\+:/'$USER':x:'$GID':/' /etc/group \
# Create $USER if it does not exist
 && if [ "$(getent passwd $UID)" = "" ]; then \
      echo "$USER:x:$UID:$GID::/home/$USER:/bin/false" >> /etc/passwd; \
      echo "$USER:!:$(($(date +%s) / 60 / 60 / 24)):0:99999:7:::" >> /etc/shadow; \
      echo "$USER:x:$GID:" >> /etc/group; \
    fi \
 && mkdir -p /home/$USER \
 && chown $UID:$GID /home/$USER \
 || true

USER $USER

ARG PYTHON_RELEASE=3.10
FROM python:${PYTHON_RELEASE}-alpine as dist
LABEL maintainer aynic.os <support+docker@asycn.io>

ARG DOCKER_BUILD_DIR=.
ARG OPERATING_SYSTEM=Linux
ARG PROCESSOR_ARCHITECTURE=x86_64
ARG PYTHON_RELEASE=3.10

WORKDIR /opt/dpgpid
COPY requirements.txt ./
RUN apk upgrade --no-cache \
 && apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/community/ --virtual .build-deps \
    build-base \
    libffi-dev \
    protobuf \
    py3-gpgme \
    swig \
 && /usr/local/bin/python${PYTHON_RELEASE} -m venv ./ \
 && ./bin/pip${PYTHON_RELEASE} install -U pip wheel \
 && ./bin/pip${PYTHON_RELEASE} install -r ./requirements.txt \
 && wget https://github.com/libp2p/go-libp2p-core/raw/master/crypto/pb/crypto.proto \
 && protoc --python_out=./lib/python${PYTHON_RELEASE}/site-packages/ crypto.proto \
 && cp -a /usr/lib/python${PYTHON_RELEASE}/site-packages/gpg ./lib/python${PYTHON_RELEASE}/site-packages/ \
 && rm -rf /root/.cache ./build ./crypto.proto \
 && apk del --no-network .build-deps \
 && find ./lib -type f -executable -exec scanelf --needed --nobanner --format '%n#p' '{}' ';' \
     |tr ',' '\n' \
     |sort -u \
     |awk 'system("[ -e /lib/"$1" -o -e /usr/lib/"$1" -o -e ./lib/python'"${PYTHON_RELEASE}"'/site-packages/*/"$1" ]") == 0 { next } { print "so:" $1 }' \
     |xargs -rt apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/community/

RUN apk add --no-cache \
    bash \
    ca-certificates \
    gettext \
    gpg \
    gpg-agent \
    libc6-compat \
    libsodium \
    make \
 && OS="$(echo ${OPERATING_SYSTEM} |awk '{print tolower($0)}')"; \
    ARCH="$(echo ${PROCESSOR_ARCHITECTURE})"; \
    wget -qO - https://github.com/koalaman/shellcheck/releases/download/stable/shellcheck-stable.${OS}.${ARCH}.tar.xz \
     |tar --strip-components 1 -C ./bin -xJf - \
 && mkdir -p /opt/shellspec \
 && wget -qO - https://github.com/shellspec/shellspec/archive/refs/heads/master.tar.gz \
     |tar --strip-components 1 -C /opt/shellspec -xzf - \
 && ln -s /opt/shellspec/shellspec ./bin/shellspec

COPY --from=ipfs/go-ipfs:v0.13.0-rc1 /usr/local/bin/ipfs ./bin/
COPY README.md ./
COPY COPYING ./
COPY Makefile ./
COPY .shellspec ./
COPY specs/ ./specs/
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

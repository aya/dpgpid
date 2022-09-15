ARG PYTHON_RELEASE=3.10
FROM python:${PYTHON_RELEASE}-alpine as dist
LABEL maintainer aynic.os <support+docker@asycn.io>

ARG DOCKER_BUILD_DIR=.
ARG OPERATING_SYSTEM=$(uname -s)
ARG PROCESSOR_ARCHITECTURE=$(uname -m)
ARG PYTHON_RELEASE=3.10

WORKDIR /opt/dpgpid
COPY requirements.txt ./
RUN apk upgrade --no-cache \
 && apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/community/ --virtual .build-deps \
    build-base \
    libffi-dev \
    py3-gpgme \
    swig \
 && /usr/local/bin/python${PYTHON_RELEASE} -m venv ./ \
 && ./bin/pip${PYTHON_RELEASE} install -U pip wheel \
 && ./bin/pip${PYTHON_RELEASE} install -r ./requirements.txt \
 && cp -a /usr/lib/python${PYTHON_RELEASE}/site-packages/gpg ./lib/python${PYTHON_RELEASE}/site-packages/ \
 && rm -rf /root/.cache ./build \
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

COPY --from=ipfs/kubo:v0.15.0 /usr/local/bin/ipfs ./bin/
COPY README.md ./
COPY COPYING ./
COPY Makefile ./
COPY .shellspec ./
COPY specs/ ./specs/
COPY dpgpid ./bin/dpgpid
COPY keygen ./bin/keygen

ENV PATH=/opt/dpgpid/bin:$PATH

ENTRYPOINT []
CMD ["bash"]

FROM dist as master
ARG UID
ARG USER
ENV PATH=/opt/dpgpid/bin:$PATH
ENV UID=${UID:-999}
ENV USER=dpgpid

# If we provide a numeric UID
RUN if [ "${UID}" -eq "${UID}" ] 2>/dev/null; then \
  # Force $UID of $USER if it exists
  if [ "$(awk -F: '$1 == "'"${USER}"'" {print $3}' /etc/passwd)" != "${UID}" ]; then \
    sed -i 's/^\('"${USER}"':x\):[0-9]\+:/\1:'"${UID}"':/' /etc/passwd; \
  fi; \
  # Create $USER if $UID does not exist
  if [ "$(awk -F: '$3 == "'"${UID}"'" {print $1}' /etc/passwd)" = "" ]; then \
    echo "${USER}:x:${UID}:${GID:-${UID}}::/home/${USER}:${SHELL:-/bin/sh}" >> /etc/passwd; \
    echo "${USER}:\!:$(($(date +%s) / 60 / 60 / 24)):0:99999:7:::" >> /etc/shadow; \
    mkdir -p /home/"${USER}"; \
  fi; \
  chown "${UID}" $(awk -F: '$1 == "'"${USER}"'" {print $(NF-1)}' /etc/passwd); \
fi

# If we provide a numeric GID
RUN if [ "${GID}" -eq "${GID}" ] 2>/dev/null; then \
  # Force $GID of $GROUP if it already exists
  if [ "$(awk -F: '$1 == "'"${GROUP}"'" {print $3}' /etc/group)" != "${GID}" ]; then \
    sed -i 's/^\('"${GROUP}"':x\):[0-9]\+:/\1:'"${GID}"':/' /etc/group; \
  fi; \
  # Create $GROUP if $GID does not exist
  if [ "$(awk -F: '$3 == "'"${GID}"'" {print $1}' /etc/group)" = "" ]; then \
    echo "${GROUP}:x:${GID}:" >> /etc/group; \
  fi; \
  # Force $GID of $USER if it exists
  if [ "$(awk -F: '$1 == "'"${USER}"'" {print $4}' /etc/passwd)" != "${GID}" ]; then \
    sed -i 's/^\('"${USER}"':x:[0-9]\+\):[0-9]\+:/\1:'"${GID}"':/' /etc/passwd; \
  fi; \
  chgrp "${GID}" $(awk -F: '$1 == "'"${USER}"'" {print $(NF-1)}' /etc/passwd); \
fi

USER $USER

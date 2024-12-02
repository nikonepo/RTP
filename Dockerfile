FROM rerand0m/cn-alpine:latest

RUN apk add iproute2 py3-pytest py3-pytest-timeout cmake go make gcc g++ libc-dev linux-headers


WORKDIR /app

COPY . /app

CMD ["pytest", "-sv"]

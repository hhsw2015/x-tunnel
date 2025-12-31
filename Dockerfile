FROM node:20-alpine3.20

WORKDIR /tmp

COPY start.sh ./

EXPOSE 3000

RUN apk update && apk add --no-cache bash openssl curl tar gcompat &&\
    chmod +x start.sh

# x-tunnel-img.playingapi.tech
CMD ["./start.sh", "eyJhIjoiODllMDYzZWYxOGQ3ZmVjZjhlY2E2NTBiYWFjNzZjYmYiLCJ0IjoiYjgyYzE4ZGEtNTllNS00N2Y2LTk0Y2MtNGMzNzQxNDI1ZGJhIiwicyI6Ik1XUTRObUZqTnprdE5UVmpNeTAwWVRObUxUazVNREF0WVRSbE5qWTFORGsxT0dZeiJ9"]

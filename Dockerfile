FROM alpine:latest
RUN apk --no-cache add ca-certificates
RUN mkdir /app
WORKDIR /app
COPY sshmux /bin/sshmux
RUN chmod +x /bin/sshmux
CMD ["/bin/sshmux"]
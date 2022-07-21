FROM kong:2.8.1-ubuntu

# LABEL description="Centos 7 + Kong 0.14 + kong-oidc plugin"

USER root

RUN apt-get update && apt-get install git

RUN apt-get -y install lua5.1 lua-socket lua-sec nano 

# gcc libssl-dev

RUN luarocks install lua-resty-openidc

RUN luarocks install lua-resty-http

RUN luarocks install kong-oidc

RUN luarocks install kong-plugin-oidc-acl

# RUN luarocks install http

# COPY ./kong_plugins/token_verifier /custom-plugins/token_verifier

# WORKDIR /custom-plugins/token_verifier

# RUN luarocks make

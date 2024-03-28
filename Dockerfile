ARG NODE_VERSION=node:19.4.0

FROM $NODE_VERSION AS dependency-base

# create destination directory
RUN mkdir -p /app
WORKDIR /app

# copy the app, note .dockerignore
#COPY package.json .
#COPY package-lock.json .
#RUN npm ci


# web image: build the SvelteKit app (adapter-node) and serve it with Node.
# Build context is ./web.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . ./
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
# adapter-node bundles the server into build/; prod deps cover anything it leaves
# external.
COPY --from=build /app/build ./build
COPY --from=build /app/package.json /app/package-lock.json ./
RUN npm ci --omit=dev
ENV PORT=3000
EXPOSE 3000
CMD ["node", "build"]

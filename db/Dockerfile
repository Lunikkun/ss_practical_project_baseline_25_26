FROM postgres:15

COPY init.sql /docker-entrypoint-initdb.d/

ENV POSTGRES_DB=docdb
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres
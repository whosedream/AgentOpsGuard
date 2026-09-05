FROM agentops-patroni-python-base:e5b65587bce7 AS python-runtime

FROM agentops-patroni-postgres-base:95206741a5b2 AS builder
COPY --from=python-runtime /usr/local /usr/local
COPY --from=patroni_wheels / /wheels/
COPY --from=fault_injector /toxiproxy-server-linux-amd64 /usr/local/bin/toxiproxy-server
COPY --from=patroni_config /requirements.txt /tmp/patroni-requirements.txt
COPY --from=patroni_config /PATRONI-LICENSE.txt /tmp/PATRONI-LICENSE.txt
COPY --from=patroni_config /TOXIPROXY-LICENSE.txt /tmp/TOXIPROXY-LICENSE.txt
COPY --from=patroni_config /start-patroni.py /usr/local/bin/start-patroni
ENV PYTHONDONTWRITEBYTECODE=1
RUN uv venv /opt/patroni --python /usr/local/bin/python \
    && uv pip install --python /opt/patroni/bin/python --no-index --find-links=/wheels \
       --require-hashes --requirements /tmp/patroni-requirements.txt \
    && chmod 0755 /usr/local/bin/toxiproxy-server /usr/local/bin/start-patroni \
    && /opt/patroni/bin/patroni --version

FROM agentops-patroni-postgres-base:95206741a5b2
COPY --from=python-runtime /usr/local /usr/local
COPY --from=builder /opt/patroni /opt/patroni
COPY --from=builder /usr/local/bin/toxiproxy-server /usr/local/bin/toxiproxy-server
COPY --from=builder /usr/local/bin/start-patroni /usr/local/bin/start-patroni
COPY --from=builder /tmp/PATRONI-LICENSE.txt /usr/share/licenses/patroni/PATRONI-LICENSE.txt
COPY --from=builder /tmp/TOXIPROXY-LICENSE.txt /usr/share/licenses/toxiproxy/TOXIPROXY-LICENSE.txt
ENV PATH="/opt/patroni/bin:/usr/lib/postgresql/16/bin:/usr/local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PATRONI_POSTGRESQL_BIN_DIR=/usr/lib/postgresql/16/bin
LABEL io.agentops.runtime="patroni-kubernetes-verification" \
      io.agentops.patroni.version="4.1.4" \
      io.agentops.toxiproxy.version="2.12.0" \
      io.agentops.postgresql.major="16"

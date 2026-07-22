FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    LANGGRAPH_STRICT_MSGPACK=true \
    OPS_DB_PATH=/private/ops.db \
    CHECKPOINT_DB_PATH=/private/checkpoints.db \
    SECRET_VAULT_DB_PATH=/private/secret_vault.db

RUN addgroup --system ops && adduser --system --ingroup ops --home /app ops

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --requirement requirements.txt

COPY --chown=ops:ops ops ./ops
COPY --chown=ops:ops prompts ./prompts
COPY --chown=ops:ops data/p1 ./data/p1
COPY --chown=ops:ops streamlit_app.py README.md ./

RUN install -d -o ops -g ops -m 0700 /private

USER ops
VOLUME ["/private"]
EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)" || exit 1

CMD ["sh", "-c", "exec streamlit run streamlit_app.py --server.address=0.0.0.0 --server.port=${PORT:-8501}"]

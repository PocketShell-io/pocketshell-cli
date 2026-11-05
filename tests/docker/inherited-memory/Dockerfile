FROM python:3.12-slim
COPY requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir --require-hashes --no-deps -r /build/requirements.txt
COPY *.whl /build/
RUN pip install --no-cache-dir --no-deps /build/pocketshell-*.whl && useradd --uid 10000 --create-home orin
COPY proof.py /proof.py
USER 10000:10000
ENTRYPOINT ["python", "/proof.py"]

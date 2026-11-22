FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY gha_pin_audit ./gha_pin_audit
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.13-slim
COPY --from=build /install /usr/local
RUN useradd --system --uid 10001 app
USER app
WORKDIR /repo
ENTRYPOINT ["gha-pin-audit"]
CMD ["."]

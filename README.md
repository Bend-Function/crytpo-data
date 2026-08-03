# Crypto Market Data Collector

中文安装、配置和当前能力说明见
[`docs/zh-CN/使用指南.md`](docs/zh-CN/使用指南.md)。

Install the locked dependency set for the role you are running:

```bash
python -m pip install --require-hashes -r requirements/collector.lock
python -m pip install --require-hashes -r requirements/materializer.lock
python -m pip install --require-hashes -r requirements/archiver.lock
python -m pip install --require-hashes -r requirements/dev.lock
```

The test suite disables network access by default. Public API smoke tests are an
explicit opt-in and never authenticate or place orders:

```bash
RUN_LIVE_API_TESTS=1 python -m pytest --force-enable-socket tests/smoke -q
```

Validate the layered configuration without contacting an exchange or creating
data directories:

```bash
collector config check config.yaml
collector config check config.yaml --json
```

The committed default uses one direct egress and requires no credentials.
Reference configurations for SOCKS traffic distribution and Aliyun OSS, S3,
or a pre-mounted WebDAV filesystem are under `config/examples/`. Secret values
must be supplied through `env:` or absolute `file:` references.

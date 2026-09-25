# Testing Pulpo

The root project keeps its CI `unittest` route dependency-free. For local
pytest collection of the core repository tests, install the root test extra:

```bash
python -m pip install -e ".[test,authority]"
python -m pytest tests -q
```

The root `tests` folder has no shared database fixture. Service tests have
their own dependency extras and should be installed and run using the
instructions in each service's `pyproject.toml` and the matching CI job.

For optional GPU correctness tests, use the same CUDA or ROCm PyTorch
environment that will run the benchmark. Avoid installing a generic PyTorch
wheel over an existing ROCm build; install pytest in that environment if it is
not already present. GPU tests skip accelerator-only cases when no GPU runtime
is available.

The zero-dependency core CI route remains:

```bash
python -W error -m unittest discover -s tests -v
```

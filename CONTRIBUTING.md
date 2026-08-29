# Contributing

Thanks for helping improve Attack Surface Mapper.

## Before opening a change

- Work only with targets and datasets you are authorised to use.
- Keep changes focused and explain the operational or reporting impact.
- Add regression coverage for parser, validator, correlation or output changes.
- Do not commit credentials, private keys, raw reports from real engagements or personal data.

## Local checks

```bash
python -m compileall -q main.py src
python -m pytest -q
python -m pip wheel --no-deps --wheel-dir dist .
```

For changes to profiles or lab behaviour, also run the relevant controlled lab validation and update the documentation and changelog.

## Pull requests

Describe:

- the problem and intended behaviour;
- the affected pipeline stages or output fields;
- tests and lab checks executed;
- any compatibility or noise/coverage trade-off.

Avoid including live target names, sensitive evidence or operational credentials in commits and pull requests.

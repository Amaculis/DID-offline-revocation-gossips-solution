How to run tests: 

# All tests
python -m pytest tests/ -v

# Individual layers (fast feedback)
python -m pytest tests/test_models.py -v     # pure data model logic
python -m pytest tests/test_metrics.py -v   # metric functions
python -m pytest tests/test_issuer.py -v    # issuer process
python -m pytest tests/test_pull.py -v      # PULL integration
python -m pytest tests/test_regression.py -v  # golden-value regression
##############
# Dependencies
#
FROM python:3.8 AS base

WORKDIR /usr/src/app

# Install poetry for dep management
RUN pip install -U pip
RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python
ENV PATH="$PATH:/root/.poetry/bin"
RUN poetry config virtualenvs.create false

# Install project manifest
COPY pyproject.toml .

# Install poetry.lock from which to build
COPY poetry.lock .

# Install production dependencies
RUN poetry install --no-dev

############
# Unit tests
#
FROM base AS test

# Install full dependencies
RUN poetry install

# Copy in the application code
COPY . .

# Simple tests
RUN echo 'Running Flake8' && \
    flake8 . && \
    echo 'Running Black' && \
    black --check --diff . && \
    # Removed and running Pylint in unit tests after project has been created
    # leave commented out if no python files exist
    # echo 'Running Pylint' && \
    # find . -name '*.py' | xargs pylint  && \
    echo 'Running Yamllint' && \
    yamllint . && \
    echo 'Running pydocstyle' && \
    pydocstyle . && \
    echo 'Running Bandit' && \
    bandit --recursive ./ --configfile .bandit.yml

# TODO(Jake): Uncomment when any tests are here
# Only uncomment if tests/ exists and there are python tests
# RUN pytest -vvv --color yes

# TODO(Jake): Enable in compose instead, probably
# ENV INTEGRATION_TESTS=true

# Run full test suite including integration
ENTRYPOINT ["echo"]

CMD ["success"]

#############
# Final image
#
# This creates a runnable CLI container
FROM python:3.8-slim AS cli

WORKDIR /usr/src/app

COPY --from=base /usr/src/app /usr/src/app
COPY --from=base /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY --from=base /usr/local/bin /usr/local/bin

# TODO(Jake): Call out the individual parts of the repo that we need, after repackaging

COPY ./ddos_deny_list .

ENTRYPOINT ["python"]

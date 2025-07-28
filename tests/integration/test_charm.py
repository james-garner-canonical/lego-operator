#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import jubilant
import pytest

logger = logging.getLogger(__name__)

APP_NAME = "lego-operator"


def test_build_and_deploy_with_jubilant(juju: jubilant.Juju, request: pytest.FixtureRequest):
    charm = Path(request.config.getoption("--charm_path")).resolve()  # type: ignore
    config = {
        "email": "example@gmail.com",
        "server": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "plugin": "namecheap",
    }
    juju.deploy(charm, app=APP_NAME, config=config)
    juju.wait(lambda status: jubilant.all_blocked(status, APP_NAME))

    secret_uri = juju.add_secret(
        "plugin-credentials", {"namecheap-api-key": "key1", "namecheap-api-user": "me"}
    )
    juju.grant_secret(secret_uri, app=APP_NAME)
    juju.config(APP_NAME, {"plugin-config-secret-id": secret_uri.unique_identifier})
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME))
    (unit_status,) = juju.status().apps[APP_NAME].units.values()
    assert unit_status.workload_status == "active"

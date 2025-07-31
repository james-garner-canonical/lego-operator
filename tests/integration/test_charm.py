#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

import logging
import pathlib
import subprocess
import urllib.request

import jubilant

logger = logging.getLogger(__name__)

APP_NAME = "lego-operator"


def test_deploy_lego(juju: jubilant.Juju, charm_path: pathlib.Path):
    def workload_status(status: jubilant.Status) -> str:
        return status.apps[APP_NAME].units[f"{APP_NAME}/0"].workload_status.current

    config = {
        "email": "example@gmail.com",
        "server": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "plugin": "namecheap",
    }
    juju.deploy(charm_path, app=APP_NAME, config=config)
    juju.wait(lambda status: workload_status(status) == "blocked")

    secret_data = {"namecheap-api-key": "key1", "namecheap-api-user": "me"}
    secret_uri = juju.add_secret("plugin-credentials", secret_data)
    juju.grant_secret(secret_uri, app=APP_NAME)
    juju.config(APP_NAME, {"plugin-config-secret-id": secret_uri.unique_identifier})
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME))

    assert workload_status(juju.status()) == "active"
    juju.remove_application(APP_NAME)


def test_deploy_functional(juju: jubilant.Juju, charm_path: pathlib.Path):

    subprocess.check_output([
        "microk8s",
        "kubectl",
        "apply",
        "-f",
        "tests/integration/pebble-deployment.yaml",
        "-f",
        "tests/integration/pebble-challtestsrv-deployment.yaml",
    ])

    uri = juju.add_secret("plugin-credentials", {"httpreq-endpoint": "http://pebble-challtestsrv:8053"})  # DNS server
    config = {
        "email": "example@example.com",
        "plugin": "httpreq",
        "server": "https://pebble:14000/dir",  # ACME server
        "plugin-config-secret-id": uri.unique_identifier,
    }
    juju.deploy(charm_path, config=config)
    juju.grant_secret("plugin-credentials", "lego")
    juju.wait(jubilant.all_active)

    # copy CA cert from letsencrypt's pebble to lego
    # pebble_ca = subprocess.check_output([
    #     "microk8s",
    #     "kubectl",
    #     "exec",
    #     "-n",
    #     "model",
    #     "pebble",
    #     "--",
    #     "cat",
    #     "/test/certs/pebble.minica.pem",
    # ])
    p = pathlib.Path("pebble-ca.pem")
    urllib.request.urlretrieve("https://raw.githubusercontent.com/letsencrypt/pebble/refs/heads/main/test/certs/pebble.minica.pem", p)
    juju.scp(p, "lego/0:/etc/ssl/certs/")
    juju.exec("c_rehash", "/etc/ssl/certs/", unit="lego/0")

    juju.deploy("tls-certificates-requirer", config={"common_name": "example.com"}, channel="edge")
    juju.integrate("lego", "tls-certificates-requirer")
    juju.wait(jubilant.all_active)

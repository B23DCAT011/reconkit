"""Tests for the orchestrator pipeline."""

import pytest
from conftest import FakePlugin

from reconkit.orchestrator import Orchestrator
from reconkit.schema import Service
from reconkit.scope import Scope, ScopeError


def test_refuses_out_of_scope_target() -> None:
    orch = Orchestrator(plugins=[FakePlugin([])], scope=Scope.from_entries(["scanme.lab"]))
    with pytest.raises(ScopeError):
        orch.run("evil.example.com")


def test_collects_services_from_plugins() -> None:
    plugin = FakePlugin([Service(port=22, name="ssh"), Service(port=80, name="http")])
    orch = Orchestrator(plugins=[plugin], scope=Scope.from_entries(["scanme.lab"]))
    run = orch.run("scanme.lab")
    assert run.target == "scanme.lab"
    assert len(run.assets) == 1
    assert {s.port for s in run.assets[0].services} == {22, 80}


def test_skips_unavailable_plugins() -> None:
    present = FakePlugin([Service(port=22)], available=True)
    missing = FakePlugin([Service(port=443)], available=False)
    orch = Orchestrator(plugins=[present, missing], scope=Scope.from_entries(["scanme.lab"]))
    run = orch.run("scanme.lab")
    assert {s.port for s in run.assets[0].services} == {22}

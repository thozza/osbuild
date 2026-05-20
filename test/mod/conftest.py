"""Common fixtures and utilities"""

import os

import pytest

from osbuild.solver.model import Repository
from osbuild.solver.request import SolverConfig


def assert_depsolve_result_equal(result1, result2):
    """
    Assert that two depsolve results are equal.

    Iterates both results' transactions in lockstep, then compares
    repositories, modules, and sbom after all transactions are consumed.
    """
    it1 = iter(result1.transactions)
    it2 = iter(result2.transactions)
    sentinel = object()
    tx_idx = 0
    while True:
        tx1 = next(it1, sentinel)
        tx2 = next(it2, sentinel)
        if tx1 is sentinel and tx2 is sentinel:
            break
        assert tx1 is not sentinel, f"result1 has fewer transactions than result2 (at index {tx_idx})"
        assert tx2 is not sentinel, f"result2 has fewer transactions than result1 (at index {tx_idx})"
        assert len(tx1) == len(tx2), (
            f"Transaction {tx_idx}: result1 has {len(tx1)} packages, result2 has {len(tx2)}"
        )
        for pkg1, pkg2 in zip(tx1, tx2):
            assert_object_equal(pkg1, pkg2)
        tx_idx += 1
    assert_object_equal(result1.repositories, result2.repositories)
    assert result1.modules == result2.modules, (
        f"modules differ:\n  result1: {result1.modules}\n  result2: {result2.modules}"
    )
    assert result1.sbom == result2.sbom, (
        f"sbom differ:\n  result1: {result1.sbom}\n  result2: {result2.sbom}"
    )


def assert_dump_result_equal(result1, result2):
    """
    Assert that two dump results are equal.
    """
    it1 = iter(result1.packages)
    it2 = iter(result2.packages)
    sentinel = object()
    while True:
        pkg1 = next(it1, sentinel)
        pkg2 = next(it2, sentinel)
        if pkg1 is sentinel and pkg2 is sentinel:
            break
        assert pkg1 is not sentinel, "result1 has fewer packages than result2"
        assert pkg2 is not sentinel, "result2 has fewer packages than result1"
        assert_object_equal(pkg1, pkg2)
    assert_object_equal(result1.repositories, result2.repositories)


def assert_object_equal(obj1, obj2):
    """
    Assert that two objects are equal.

    If the objects are not equal, print the differences.
    """
    assert isinstance(obj1, type(obj2)), f"Objects are not of the same type: {type(obj1)} != {type(obj2)}"
    if obj1 != obj2:
        differences = []
        all_keys = set(vars(obj1).keys()) | set(vars(obj2).keys())
        for key in sorted(all_keys):
            val1 = vars(obj1).get(key)
            val2 = vars(obj2).get(key)
            if val1 != val2:
                differences.append(f"  {key}:")
                differences.append(f"    OBJ1: {val1!r}")
                differences.append(f"    OBJ2: {val2!r}")
        assert False, "Objects are not equal:\n" + "\n".join(differences)


def instantiate_solver(solver_class, cachedir, persistdir, repo_servers):
    """Prepare a solver object for testing."""
    repo_configs = [Repository.from_request(repo_id=r["name"], baseurl=[r["address"]]) for r in repo_servers]
    return solver_class(
        config=SolverConfig(
            arch="x86_64",
            releasever="9",
            module_platform_id="platform:el9",
            cachedir=os.fspath(cachedir),
            repos=repo_configs,
        ),
        persistdir=os.fspath(persistdir),
    )


@pytest.fixture
def solver(tmp_path, repo_servers, request):
    """Instantiate a solver from the parametrized solver class.

    Use with @pytest.mark.parametrize("solver", ..., indirect=True).
    Supports pytest.param(..., marks=pytest.mark.xfail(...)) for
    per-solver-class marks.
    """
    cachedir = tmp_path / "cache"
    persistdir = tmp_path / "persist"
    return instantiate_solver(request.param, cachedir, persistdir, repo_servers)

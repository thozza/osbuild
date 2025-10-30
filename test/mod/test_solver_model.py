from datetime import datetime, timezone

import pytest

from osbuild.solver.model import (
    Checksum,
    Repository,
    RPMDependency,
    RPMPackage,
    SolverAPIResponse,
    SolverAPIResponseCommand,
)

TEST_CHECKSUM = Checksum("sha256", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

TEST_PACKAGES = [
    RPMPackage(
        "PackageA",
        "1.0.0",
        "1.fc40",
        "x86_64",
        epoch=0,
        group="core",
        download_size=1000,
        install_size=1000,
        license="GPL-2.0-only",
        source_rpm="PackageA-1.0.0-1.fc40.src.rpm",
        build_time=1714857600,
        packager="John Foo <john.foo@example.com>",
        vendor="Example Inc.",
        url="https://example.com/packagea",
        summary="Package A",
        description="Package A is a package",
        provides=[RPMDependency("PackageA", "=", "1.0.0")],
        requires=[
            RPMDependency("PackageB", ">=", "2.0.0"),
            RPMDependency("PackageC", ">=", "3.0.0"),
        ],
        requires_pre=[RPMDependency("PackageC", ">=", "3.0.0")],
        conflicts=[RPMDependency("PackageD", ">= 5.0.0")],
        obsoletes=[RPMDependency("PackageE", ">= 6.0.0")],
        regular_requires=[RPMDependency("PackageB", ">=", "2.0.0")],
        recommends=[RPMDependency("PackageF", ">= 8.0.0")],
        suggests=[RPMDependency("PackageG", ">= 9.0.0")],
        enhances=[RPMDependency("PackageH", ">= 10.0.0")],
        supplements=[RPMDependency("PackageI", ">= 11.0.0")],
        files=[
            "/usr/bin/packagea",
            "/usr/share/packagea/README",
        ],
        base_url="https://example.com/repo1",
        location="Packages/PackageA-1.0.0-1.fc40.x86_64.rpm",
        remote_locations=["https://example.com/repo1/Packages/PackageA-1.0.0-1.fc40.x86_64.rpm"],
        checksum=TEST_CHECKSUM,
        header_checksum=TEST_CHECKSUM,
        repo_id="repo1"
    ),
    RPMPackage(
        "PackageB",
        "2.0.0",
        "2.fc40",
        "x86_64",
        epoch=2,
        group="core",
        download_size=2000,
        install_size=2000,
        license="GPL-2.0-only",
        source_rpm="PackageB-2.0.0-2.fc40.src.rpm",
        build_time=1714857600,
        packager="John Foo <john.foo@example.com>",
        vendor="Example Inc.",
        url="https://example.com/packageb",
        summary="Package B",
        description="Package B is a package",
        provides=[RPMDependency("PackageB", "=", "2.0.0")],
        files=[
            "/usr/bin/packageb",
            "/usr/share/packageb/README",
        ],
        base_url="https://example.com/repo2",
        location="Packages/PackageB-2.0.0-2.fc40.x86_64.rpm",
        remote_locations=["https://example.com/repo2/Packages/PackageB-2.0.0-2.fc40.x86_64.rpm"],
        checksum=TEST_CHECKSUM,
        header_checksum=TEST_CHECKSUM,
        repo_id="repo2",
    ),
    RPMPackage(
        "PackageC",
        "3.0.0",
        "3.fc40",
        "x86_64",
        epoch=3,
        group="core",
        download_size=3000,
        install_size=3000,
        license="GPL-2.0-only",
        source_rpm="PackageC-3.0.0-3.fc40.src.rpm",
        build_time=1714857600,
        packager="John Foo <john.foo@example.com>",
        vendor="Example Inc.",
        url="https://example.com/packagec",
        summary="Package C",
        description="Package C is a package",
        provides=[RPMDependency("PackageC", "=", "3.0.0")],
        files=[
            "/usr/bin/packagec",
            "/usr/share/packagec/README",
        ],
        base_url="https://example.com/repo1",
        location="Packages/PackageC-3.0.0-3.fc40.x86_64.rpm",
        remote_locations=["https://example.com/repo1/Packages/PackageC-3.0.0-3.fc40.x86_64.rpm"],
        checksum=TEST_CHECKSUM,
        header_checksum=TEST_CHECKSUM,
        repo_id="repo1",
    ),
    RPMPackage(
        "PackageD",
        "4.0.0",
        "4.fc40",
        "x86_64",
        epoch=4,
        group="core",
        download_size=4000,
        install_size=4000,
        license="GPL-2.0-only",
        source_rpm="PackageD-4.0.0-4.fc40.src.rpm",
        build_time=1714857600,
        packager="John Foo <john.foo@example.com>",
        vendor="Example Inc.",
        summary="Package D",
        description="Package D is a package",
        provides=[RPMDependency("PackageD", "=", "4.0.0")],
        files=[
            "/usr/bin/packaged",
            "/usr/share/packaged/README",
        ],
        base_url="https://example.com/repo1",
        location="Packages/PackageD-4.0.0-4.fc40.x86_64.rpm",
        remote_locations=["https://example.com/repo1/Packages/PackageD-4.0.0-4.fc40.x86_64.rpm"],
        checksum=TEST_CHECKSUM,
        header_checksum=TEST_CHECKSUM,
        repo_id="repo1",
    ),
]

TEST_REPOSITORIES = [
    Repository(
        "repo1",
        "Repo 1",
        baseurl=["https://example.com/repo1"],
        metalink="https://example.com/repo1/metalink",
        mirrorlist="https://example.com/repo1/mirrorlist",
        gpgcheck=True,
        repo_gpgcheck=True,
        gpgkeys=["https://example.com/repo1/RPM-GPG-KEY"],
        sslverify=True,
        sslcacert="https://example.com/repo1/ca.crt",
        sslclientkey="https://example.com/repo1/client.key",
        sslclientcert="https://example.com/repo1/client.crt",
    ),
    Repository(
        "repo2",
        "Repo 2",
        baseurl=["https://example.com/repo2"],
        metalink="https://example.com/repo2/metalink",
        mirrorlist="https://example.com/repo2/mirrorlist",
        gpgcheck=False,
        repo_gpgcheck=True,
        gpgkeys=["https://example.com/repo2/RPM-GPG-KEY"],
        sslverify=False,
        sslcacert="https://example.com/repo2/ca.crt",
        sslclientkey="https://example.com/repo2/client.key",
        sslclientcert="https://example.com/repo2/client.crt",
    ),
]


@pytest.mark.parametrize("command", [SolverAPIResponseCommand.DUMP, SolverAPIResponseCommand.SEARCH])
def test_solver_response_v1_dump_search(command):
    response = SolverAPIResponse(packages=TEST_PACKAGES, repositories=TEST_REPOSITORIES)
    # NB: the response is a list of dictionaries
    response_dict = response.as_dict(command)
    assert isinstance(response_dict, list)
    assert len(response_dict) == len(TEST_PACKAGES)
    for idx, pkg in enumerate(response_dict):
        assert sorted(list(pkg.keys())) == [
            "arch",
            "buildtime",
            "description",
            "epoch",
            "license",
            "name",
            "release",
            "repo_id",
            "summary",
            "url",
            "version",
        ]
        assert pkg["name"] == TEST_PACKAGES[idx].name
        assert pkg["summary"] == TEST_PACKAGES[idx].summary
        assert pkg["description"] == TEST_PACKAGES[idx].description
        assert pkg["url"] == TEST_PACKAGES[idx].url
        assert pkg["repo_id"] == TEST_PACKAGES[idx].repo_id
        assert pkg["epoch"] == TEST_PACKAGES[idx].epoch
        assert pkg["version"] == TEST_PACKAGES[idx].version
        assert pkg["release"] == TEST_PACKAGES[idx].release
        assert pkg["arch"] == TEST_PACKAGES[idx].arch
        assert pkg["buildtime"] == datetime.fromtimestamp(
            TEST_PACKAGES[idx].build_time, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        assert pkg["license"] == TEST_PACKAGES[idx].license


@pytest.mark.parametrize("modules", [
    None,
    {"module1": "solver specific data"}
], ids=["no-modules", "with-modules"])
@pytest.mark.parametrize("solver", ["dnf5", "dnf", None])
def test_solver_response_v1_depsolve(solver, modules):
    kwargs = {}
    if modules:
        kwargs["modules"] = modules
    response = SolverAPIResponse(packages=TEST_PACKAGES, repositories=TEST_REPOSITORIES, solver=solver, **kwargs)
    response_dict = response.as_dict(SolverAPIResponseCommand.DEPSOLVE)
    assert list(response_dict.keys()) == ["solver", "packages", "repos", "modules"]

    if modules:
        assert response_dict["modules"] == modules
    else:
        assert response_dict["modules"] == {}

    assert response_dict["solver"] == solver if solver else "unknown"
    assert len(response_dict["packages"]) == len(TEST_PACKAGES)
    for idx, pkg in enumerate(response_dict["packages"]):
        assert sorted(list(pkg.keys())) == [
            "arch",
            "checksum",
            "epoch",
            "name",
            "path",
            "release",
            "remote_location",
            "repo_id",
            "version",
        ]
        assert pkg["name"] == TEST_PACKAGES[idx].name
        assert pkg["epoch"] == TEST_PACKAGES[idx].epoch
        assert pkg["version"] == TEST_PACKAGES[idx].version
        assert pkg["release"] == TEST_PACKAGES[idx].release
        assert pkg["arch"] == TEST_PACKAGES[idx].arch
        assert pkg["repo_id"] == TEST_PACKAGES[idx].repo_id
        assert pkg["path"] == TEST_PACKAGES[idx].location
        assert pkg["remote_location"] == TEST_PACKAGES[idx].remote_locations
        assert pkg["checksum"] == str(TEST_PACKAGES[idx].checksum)
    assert len(response_dict["repos"]) == len(TEST_REPOSITORIES)
    for idx, repo in enumerate(response_dict["repos"]):
        assert sorted(list(repo.keys())) == [
            "baseurl",
            "gpgcheck",
            "gpgkeys",
            "id",
            "metalink",
            "mirrorlist",
            "name",
            "repo_gpgcheck",
            "sslcacert",
            "sslclientcert",
            "sslclientkey",
            "sslverify",
        ]
        assert repo["id"] == TEST_REPOSITORIES[idx].repo_id
        assert repo["name"] == TEST_REPOSITORIES[idx].name
        assert repo["baseurl"] == TEST_REPOSITORIES[idx].baseurl
        assert repo["metalink"] == TEST_REPOSITORIES[idx].metalink
        assert repo["mirrorlist"] == TEST_REPOSITORIES[idx].mirrorlist
        assert repo["gpgcheck"] == TEST_REPOSITORIES[idx].gpgcheck
        assert repo["repo_gpgcheck"] == TEST_REPOSITORIES[idx].repo_gpgcheck
        assert repo["gpgkeys"] == TEST_REPOSITORIES[idx].gpgkeys
        assert repo["sslverify"] == TEST_REPOSITORIES[idx].sslverify
        assert repo["sslcacert"] == TEST_REPOSITORIES[idx].sslcacert
        assert repo["sslclientkey"] == TEST_REPOSITORIES[idx].sslclientkey
        assert repo["sslclientcert"] == TEST_REPOSITORIES[idx].sslclientcert

"""
Collection of data classes used to represent the API model of the solver
"""

from datetime import datetime, timezone
from enum import Enum, auto
from typing import List, Union


class SolverAPIResponseCommand(Enum):
    DUMP = auto()
    SEARCH = auto()
    DEPSOLVE = auto()

    def __str__(self) -> str:
        return self.name.lower()

    @staticmethod
    def from_str(name: str) -> "SolverAPIResponseCommand":
        try:
            return SolverAPIResponseCommand[name.upper()]
        except KeyError as e:
            raise ValueError(f"Invalid solver API response command: {name}") from e


# pylint: disable=too-many-instance-attributes
class Repository:
    """Represents a DNF / YUM repository"""

    def __init__(self, repo_id: str, name: str, baseurl: List[str], **kwargs) -> None:
        self.repo_id = repo_id
        self.name = name
        self.baseurl = baseurl
        self.metalink = kwargs.get("metalink", "")
        self.mirrorlist = kwargs.get("mirrorlist", "")
        self.gpgcheck = kwargs.get("gpgcheck", None)
        self.repo_gpgcheck = kwargs.get("repo_gpgcheck", None)
        self.gpgkeys = kwargs.get("gpgkeys", [])
        self.sslverify = kwargs.get("sslverify", None)
        self.sslcacert = kwargs.get("sslcacert", "")
        self.sslclientkey = kwargs.get("sslclientkey", "")
        self.sslclientcert = kwargs.get("sslclientcert", "")

    def as_dict(self) -> dict:
        return {
            "id": self.repo_id,
            "name": self.name,
            "baseurl": self.baseurl,
            "metalink": self.metalink,
            "mirrorlist": self.mirrorlist,
            "gpgcheck": self.gpgcheck,
            "repo_gpgcheck": self.repo_gpgcheck,
            "gpgkeys": self.gpgkeys,
            "sslverify": self.sslverify,
            "sslcacert": self.sslcacert,
            "sslclientkey": self.sslclientkey,
            "sslclientcert": self.sslclientcert,
        }


class RPMDependency:
    """Represents an RPM dependency or provided capability."""

    def __init__(self, name: str, relation: str = "", version: str = "") -> None:
        self.name = name
        self.relation = relation
        self.version = version

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "relation": self.relation,
            "version": self.version
        }


class Checksum:
    """Reresents a checksum used by RPM packages."""

    def __init__(self, checksum_type: str, value: str) -> None:
        self.checksum_type = checksum_type
        self.value = value

    def __str__(self) -> str:
        return f"{self.checksum_type}:{self.value}"

    def as_dict(self) -> dict:
        return {
            "type": self.checksum_type,
            "value": self.value
        }


# pylint: disable=too-many-instance-attributes
class RPMPackage:
    """Represents an RPM package"""

    def __init__(self, name: str, version: str, release: str, arch: str, **kwargs) -> None:
        self.name = name
        self.version = version
        self.release = release
        self.arch = arch

        self.epoch = kwargs.get("epoch", 0)
        self.group = kwargs.get("group", "")
        self.download_size = kwargs.get("download_size", 0)
        self.install_size = kwargs.get("install_size", 0)
        self.license = kwargs.get("license", "")
        self.source_rpm = kwargs.get("source_rpm", "")
        self.build_time = kwargs.get("build_time", 0)
        self.packager = kwargs.get("packager", "")
        self.vendor = kwargs.get("vendor", "")

        # RPM package URL (project home address)
        self.url = kwargs.get("url", "")

        self.summary = kwargs.get("summary", "")
        self.description = kwargs.get("description", "")

        # Regular dependencies
        self.provides = kwargs.get("provides", [])
        self.requires = kwargs.get("requires", [])
        self.requires_pre = kwargs.get("requires_pre", [])
        self.conflicts = kwargs.get("conflicts", [])
        self.obsoletes = kwargs.get("obsoletes", [])
        self.regular_requires = kwargs.get("regular_requires", [])

        # Weak dependencies
        self.recommends = kwargs.get("recommends", [])
        self.suggests = kwargs.get("suggests", [])
        self.enhances = kwargs.get("enhances", [])
        self.supplements = kwargs.get("supplements", [])

        # List of files and directories the RPM package contains
        self.files = kwargs.get("files", [])

        # RPM package baseurl from repodata
        self.base_url = kwargs.get("base_url", "")
        # RPM package relative path/location from repodata
        self.location = kwargs.get("location", "")
        # RPM package remote location where the package can be download from
        self.remote_locations = kwargs.get("remote_locations", [])

        # Checksum object representing RPM package checksum and its type
        self.checksum = kwargs.get("checksum", None)
        # Checksum object representing RPM package header checksum and its type
        self.header_checksum = kwargs.get("header_checksum", None)
        # Repository ID this package belongs to
        self.repo_id = kwargs.get("repo_id", "")
        # Resolved reason why a package was / would be installed.
        self.reason = kwargs.get("reason", "")

    @staticmethod
    def _timestamp_to_rfc3339(timestamp: int) -> str:
        return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    def _as_dict_v1_dump_search(self) -> dict:
        """
        Returns a dictionary representation of the RPM package for the v1 DUMP and SEARCH commands.
        """
        return {
            "name": self.name,
            "summary": self.summary,
            "description": self.description,
            # DNF4 returns None, DNF5 returns an empty string, so we unify the behavior by returning an empty string
            "url": self.url if self.url else "",
            "repo_id": self.repo_id,
            "epoch": self.epoch,
            "version": self.version,
            "release": self.release,
            "arch": self.arch,
            "buildtime": self._timestamp_to_rfc3339(self.build_time),
            "license": self.license,
        }

    def _as_dict_v1_depsolve(self) -> dict:
        """
        Returns a dictionary representation of the RPM package for the v1 DEPSOLVE command.
        """
        return {
            "name": self.name,
            "epoch": self.epoch,
            "version": self.version,
            "release": self.release,
            "arch": self.arch,
            "repo_id": self.repo_id,
            "path": self.location,
            "remote_location": self.remote_locations,
            "checksum": str(self.checksum),
        }

    def as_dict(self, command: SolverAPIResponseCommand) -> dict:
        """
        Returns a dictionary representation of the RPM package. The dictionary is intended to be used as a JSON object.
        The `command` parameter is used to determine which fields to include in the dictionary,
        specifically for the v1 API response, where each command has its own set of fields.
        """
        if command == SolverAPIResponseCommand.DUMP:
            return self._as_dict_v1_dump_search()
        if command == SolverAPIResponseCommand.DEPSOLVE:
            return self._as_dict_v1_depsolve()
        if command == SolverAPIResponseCommand.SEARCH:
            return self._as_dict_v1_dump_search()
        raise ValueError(f"Invalid command: {command}")


class SolverAPIResponse:
    """
    Abstracts the Solver API responses and provides a common interface for all solver API responses.
    """

    def __init__(self, packages: List[RPMPackage], repositories: List[Repository], **kwargs) -> None:
        self.packages = packages
        self.repositories = repositories
        self.solver = kwargs.get("solver", "unknown")
        self.sbom = kwargs.get("sbom", None)
        # Modularity response is solver specific, so we don't use any data class
        # to represent it. The solver implementation is responsible for handling
        # the API versioning for this field.
        self.modules = kwargs.get("modules", {})

    def as_dict(self, command: SolverAPIResponseCommand) -> Union[dict, list[dict]]:
        """
        Returns a JSON serializable representation of the Solver API response.
        By default, the response is a dictionary, however, in some cases, the response
        it is a list of dictionaries.

        The `command` parameter is used to determine which fields to include in the dictionary,
        specifically for the v1 API response, where each command has its own set of fields.
        """
        if command in [SolverAPIResponseCommand.DUMP, SolverAPIResponseCommand.SEARCH]:
            return [package.as_dict(command) for package in self.packages]
        if command == SolverAPIResponseCommand.DEPSOLVE:
            d = {
                "solver": self.solver,
                "packages": [package.as_dict(command) for package in self.packages],
                "repos": {repository.repo_id: repository.as_dict() for repository in self.repositories},
                "modules": self.modules,
            }
            if self.sbom:
                d["sbom"] = self.sbom
            return d
        raise ValueError(f"Invalid command: {command}")

from datetime import datetime
from typing import Callable, Dict, List, Optional, Union
from uuid import uuid4

import osbuild
import osbuild.util.sbom.model as sbom_model
import osbuild.util.sbom.spdx2 as spdx2


def _get_spdx_licensing() -> Callable:
    """
    Return the get_spdx_licensing function from the license-expression package.
    This is a helper function to make testing and mocking easier.
    """
    from license_expression import get_spdx_licensing
    return get_spdx_licensing


class SpdxLicenseExpressionFactory:
    """
    Factory for creating SPDX license expressions from license strings.

    This factory uses the license-expression package to parse license strings and convert them to SPDX license, if
    possible.

    The factory also keeps track of all extracted licensing information objects that were created during the conversion
    process. The extracted licensing information objects are stored in a dictionary, where the key is the license
    reference ID and the value is the ExtractedLicensingInfo object.
    """

    def __init__(self, license_index_location=None):
        self._extracted_license_infos : Dict[str, spdx2.ExtractedLicensingInfo]  = dict()
        self._spdx_licensing = None
        try:
            get_spdx_licensing = _get_spdx_licensing()
            if license_index_location:
                self._spdx_licensing = get_spdx_licensing(license_index_location)
            else:
                self._spdx_licensing = get_spdx_licensing()
        except ImportError:
            # XXX Should we raise an exception here if the license_index_location is not None?
            pass

    def _to_extracted_license_info(self, license: str) -> spdx2.ExtractedLicensingInfo:
        license = spdx2.ExtractedLicensingInfo(license)
        return self._extracted_license_infos.setdefault(license.license_ref_id, license)

    def ensure_license_expression(self, license: str) -> Union[str, spdx2.ExtractedLicensingInfo]:
        """
        Convert a license string to a valid SPDX license expression or wrap it in an ExtractedLicensingInfo object.

        This function uses the license-expression package to parse the license string and convert it to an SPDX license
        expression. If the license string can't be parsed and converted to an SPDX license expression, it is wrapped in an
        ExtractedLicensingInfo object.

        If the license-expression package is not available, the license string is always wrapped in an
        ExtractedLicensingInfo object.
        """
        if self._spdx_licensing is None:
            return self._to_extracted_license_info(license)

        try:
            license_expression = self._spdx_licensing.parse(license, validate=True, strict=True)
        except Exception:
            return self._to_extracted_license_info(license)

        return str(license_expression)

    def extracted_license_infos(self) -> List[spdx2.ExtractedLicensingInfo]:
        """
        Return a list of all extracted licensing information objects that were created during the conversion process.
        """
        return list(self._extracted_license_infos.values())


def spdx2_checksum_algorithm(algorithm: sbom_model.ChecksumAlgorithm) -> spdx2.ChecksumAlgorithm:
    if algorithm == sbom_model.ChecksumAlgorithm.SHA1:
        return spdx2.ChecksumAlgorithm.SHA1
    if algorithm == sbom_model.ChecksumAlgorithm.SHA224:
        return spdx2.ChecksumAlgorithm.SHA224
    if algorithm == sbom_model.ChecksumAlgorithm.SHA256:
        return spdx2.ChecksumAlgorithm.SHA256
    if algorithm == sbom_model.ChecksumAlgorithm.SHA384:
        return spdx2.ChecksumAlgorithm.SHA384
    if algorithm == sbom_model.ChecksumAlgorithm.SHA512:
        return spdx2.ChecksumAlgorithm.SHA512
    if algorithm == sbom_model.ChecksumAlgorithm.MD5:
        return spdx2.ChecksumAlgorithm.MD5
    raise ValueError(f"Unknown checksum algorithm: {algorithm}")


def create_spdx2_document():
    tool = f"osbuild-{osbuild.__version__}"
    doc_name = f"sbom-by-{tool}"

    ci = spdx2.CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id="SPDXRef-DOCUMENT",
        name=doc_name,
        data_license="CC0-1.0",
        document_namespace=f"https://osbuild.org/spdxdocs/{doc_name}-{uuid4()}",
        creators=[spdx2.Creator(spdx2.CreatorType.TOOL, tool)],
        created=datetime.now(),
    )
    doc = spdx2.Document(ci)

    return doc


def sbom_pkgset_to_spdx2_doc(
        pkgset: List[sbom_model.BasePackage],
        license_expr_factory: Optional[SpdxLicenseExpressionFactory] = None
        ) -> spdx2.Document:
    doc = create_spdx2_document()
    relationships = []
    license_expr_factory = license_expr_factory or SpdxLicenseExpressionFactory()

    for pkg in pkgset:

        download_location: Union[str, spdx2.NoAssertionValue] = spdx2.NoAssertionValue()
        if pkg.download_url:
            download_location = pkg.download_url

        license_declared = license_expr_factory.ensure_license_expression(pkg.license_declared)

        p = spdx2.Package(
            spdx_id=f"SPDXRef-{pkg.uuid()}",
            name=pkg.name,
            download_location=download_location,
            version=pkg.version,
            files_analyzed=False,
            license_declared=license_declared,
            external_references=[
                spdx2.ExternalPackageRef(
                    category=spdx2.ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type="purl",
                    locator=pkg.purl(),
                )
            ]
        )

        if pkg.homepage:
            p.homepage = pkg.homepage

        if pkg.summary:
            p.summary = pkg.summary

        if pkg.description:
            p.description = pkg.description

        if pkg.source_info():
            p.source_info = pkg.source_info()

        for hash_type, hash_value in pkg.checksums.items():
            p.checksums.append(
                spdx2.Checksum(
                    algorithm=spdx2_checksum_algorithm(hash_type),
                    value=hash_value,
                )
            )

        if pkg.build_date:
            p.built_date = pkg.build_date

        doc.packages.append(p)

        relationships.append(
            spdx2.Relationship(
                spdx_element_id=doc.creation_info.spdx_id,
                relationship_type=spdx2.RelationshipType.DESCRIBES,
                related_spdx_element_id=p.spdx_id,
            )
        )

        for dep in sorted(pkg.depends_on, key=lambda x: x.uuid()):
            relationships.append(
                spdx2.Relationship(
                    spdx_element_id=p.spdx_id,
                    relationship_type=spdx2.RelationshipType.DEPENDS_ON,
                    related_spdx_element_id=f"SPDXRef-{dep.uuid()}",
                )
            )

        for optional_dep in sorted(pkg.optional_depends_on, key=lambda x: x.uuid()):
            relationships.append(
                spdx2.Relationship(
                    spdx_element_id=f"SPDXRef-{optional_dep.uuid()}",
                    relationship_type=spdx2.RelationshipType.OPTIONAL_DEPENDENCY_OF,
                    related_spdx_element_id=p.spdx_id,
                )
            )

    doc.relationships = relationships

    extracted_license_infos = license_expr_factory.extracted_license_infos()
    if len(extracted_license_infos) > 0:
        doc.extracted_licensing_infos = extracted_license_infos

    return doc

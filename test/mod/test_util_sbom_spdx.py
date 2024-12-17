import os
from unittest.mock import patch, MagicMock

import pytest

import osbuild
from osbuild.util.sbom.spdx import create_spdx2_document, sbom_pkgset_to_spdx2_doc, spdx2_checksum_algorithm, SpdxLicenseExpressionFactory
from osbuild.util.sbom.spdx2.model import CreatorType, ExternalPackageRefCategory, RelationshipType, ExtractedLicensingInfo

testutil_dnf4 = pytest.importorskip("osbuild.testutil.dnf4")
bom_dnf = pytest.importorskip("osbuild.util.sbom.dnf")


def _mock_get_spdx_licensing(exception=False):
    mm = MagicMock()
    mm.parse.return_value = "MIT"
    if exception:
        mm.side_effect = ImportError("license_expression not available")
    return mm


@pytest.mark.parametrize("licensing_available", (True, False))
def test_spdxlicenseexpressionfactory_license_expression_availability(licensing_available):
    with patch("osbuild.util.sbom.spdx._get_spdx_licensing",
               new_callable=lambda: _mock_get_spdx_licensing(licensing_available)) as mocked_licensing:
        lf = SpdxLicenseExpressionFactory()
        assert mocked_licensing.call_count == 1
        license_expression = lf.ensure_license_expression("MIT")

        if licensing_available:
            # The license string should be a SPDX license expression string.
            assert license_expression == "MIT"
            assert len(lf.extracted_license_infos()) == 0
        else:
            # The license string should be wrapped in an ExtractedLicensingInfo,
            # because the license-expression package is not available.
            assert isinstance(license_expression, ExtractedLicensingInfo)
            assert license_expression.extracted_text == "MIT"
            assert len(lf.extracted_license_infos()) == 1


def test_create_spdx2_document():
    doc1 = create_spdx2_document()

    assert doc1.creation_info.spdx_version == "SPDX-2.3"
    assert doc1.creation_info.spdx_id == "SPDXRef-DOCUMENT"
    assert doc1.creation_info.name == f"sbom-by-osbuild-{osbuild.__version__}"
    assert doc1.creation_info.data_license == "CC0-1.0"
    assert doc1.creation_info.document_namespace.startswith("https://osbuild.org/spdxdocs/sbom-by-osbuild-")
    assert len(doc1.creation_info.creators) == 1
    assert doc1.creation_info.creators[0].creator_type == CreatorType.TOOL
    assert doc1.creation_info.creators[0].name == f"osbuild-{osbuild.__version__}"
    assert doc1.creation_info.created

    doc2 = create_spdx2_document()
    assert doc1.creation_info.document_namespace != doc2.creation_info.document_namespace
    assert doc1.creation_info.created != doc2.creation_info.created

    doc1_dict = doc1.to_dict()
    doc2_dict = doc2.to_dict()
    del doc1_dict["creationInfo"]["created"]
    del doc2_dict["creationInfo"]["created"]
    del doc1_dict["documentNamespace"]
    del doc2_dict["documentNamespace"]
    assert doc1_dict == doc2_dict


@pytest.mark.parametrize("licensing_available", (True, False))
def test_sbom_pkgset_to_spdx2_doc(licensing_available):
    dnf_pkgset = testutil_dnf4.depsolve_pkgset([os.path.abspath("./test/data/testrepos/baseos")], ["bash"])
    bom_pkgset = bom_dnf.dnf_pkgset_to_sbom_pkgset(dnf_pkgset)

    with patch("osbuild.util.sbom.spdx._get_spdx_licensing",
               new_callable=lambda: _mock_get_spdx_licensing(licensing_available)) as spdx_licensing:
        doc = sbom_pkgset_to_spdx2_doc(bom_pkgset)
        extracted_licensing_infos = set()
        assert len(doc.packages) == len(bom_pkgset)
        for spdx_pkg, bom_pkg in zip(doc.packages, bom_pkgset):
            assert spdx_pkg.spdx_id == f"SPDXRef-{bom_pkg.uuid()}"
            assert spdx_pkg.name == bom_pkg.name
            assert spdx_pkg.version == bom_pkg.version
            assert not spdx_pkg.files_analyzed
            assert spdx_pkg.download_location == bom_pkg.download_url
            assert spdx_pkg.homepage == bom_pkg.homepage
            assert spdx_pkg.summary == bom_pkg.summary
            assert spdx_pkg.description == bom_pkg.description
            assert spdx_pkg.source_info == bom_pkg.source_info()
            assert spdx_pkg.built_date == bom_pkg.build_date

            if licensing_available:
                # All licenses are wrapped in ExtractedLicensingInfo objects
                assert isinstance(spdx_pkg.license_declared, ExtractedLicensingInfo)
                extracted_licensing_infos.add(spdx_pkg.license_declared)
            else:
                # All parseable licenses are converted to SPDX license expressions represented as strings
                # this is when spdx_licensing parse() method does not raise any exception
                try:
                    license_expression = spdx_licensing.parse(bom_pkg.license_declared, validate=True, strict=True)
                    assert spdx_pkg.license_declared == str(license_expression)
                except Exception:
                    assert isinstance(spdx_pkg.license_declared, ExtractedLicensingInfo)
                    extracted_licensing_infos.add(spdx_pkg.license_declared)

            assert len(spdx_pkg.checksums) == 1
            assert spdx_pkg.checksums[0].algorithm == spdx2_checksum_algorithm(list(bom_pkg.checksums.keys())[0])
            assert spdx_pkg.checksums[0].value == list(bom_pkg.checksums.values())[0]

            assert len(spdx_pkg.external_references) == 1
            assert spdx_pkg.external_references[0].category == ExternalPackageRefCategory.PACKAGE_MANAGER
            assert spdx_pkg.external_references[0].reference_type == "purl"
            assert spdx_pkg.external_references[0].locator == bom_pkg.purl()

        assert len([rel for rel in doc.relationships if rel.relationship_type ==
                    RelationshipType.DESCRIBES]) == len(bom_pkgset)

        deps_count = sum(len(bom_pkg.depends_on) for bom_pkg in bom_pkgset)
        assert len([rel for rel in doc.relationships if rel.relationship_type ==
                    RelationshipType.DEPENDS_ON]) == deps_count

        optional_deps_count = sum(len(bom_pkg.optional_depends_on) for bom_pkg in bom_pkgset)
        assert len([rel for rel in doc.relationships if rel.relationship_type ==
                    RelationshipType.OPTIONAL_DEPENDENCY_OF]) == optional_deps_count

        assert sorted(extracted_licensing_infos, key=lambda x: x.license_ref_id) == \
            sorted(doc.extracted_licensing_infos, key=lambda x: x.license_ref_id)

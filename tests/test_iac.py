import unittest

from cloudguard.iac import (
    MAX_IAC_INPUT_BYTES,
    IaCDiagnosticSeverity,
    IaCDocument,
    IaCInput,
)
from cloudguard.terraform import TerraformAdapter, TerraformParser


class IaCInputTests(unittest.TestCase):
    def test_accepts_one_document(self) -> None:
        iac_input = IaCInput(
            (IaCDocument("main.tf", 'resource "aws_s3_bucket" "logs" {}'),)
        )

        self.assertEqual(iac_input.display_name, "main.tf")
        self.assertEqual(len(iac_input.documents), 1)

    def test_multiple_documents_are_ordered_deterministically(self) -> None:
        first = IaCDocument("a.tf", 'resource "aws_s3_bucket" "a" {}')
        second = IaCDocument("b.tf", 'resource "aws_s3_bucket" "b" {}')

        left = IaCInput((second, first))
        right = IaCInput((first, second))

        self.assertEqual(left.documents, right.documents)
        self.assertEqual(left.content_digest, right.content_digest)
        self.assertEqual(left.display_name, "a.tf (+1 documents)")

    def test_rejects_empty_and_duplicate_documents(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            IaCInput(())
        with self.assertRaisesRegex(ValueError, "content must be"):
            IaCDocument("main.tf", " ")
        document = IaCDocument("main.tf", "resource {}")
        with self.assertRaisesRegex(ValueError, "names must be unique"):
            IaCInput((document, document))

    def test_rejects_total_size_over_bound(self) -> None:
        oversized = "x" * MAX_IAC_INPUT_BYTES

        with self.assertRaisesRegex(ValueError, "IaC input exceeds"):
            IaCInput((IaCDocument("main.tf", oversized),))


class TerraformAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = TerraformAdapter()

    def test_preserves_single_file_parser_output(self) -> None:
        content = '''
module "network" {
  source = "./network"
}
resource "aws_s3_bucket" "logs" {
  bucket = "example-logs"
}
'''
        parser_result = TerraformParser().parse_text(content, filename="main.tf")
        adapter_result = self.adapter.parse(
            IaCInput((IaCDocument("main.tf", content),))
        )

        self.assertEqual(
            adapter_result.architecture.resources,
            parser_result.architecture.resources,
        )
        self.assertEqual(
            adapter_result.declared_evidence,
            parser_result.evidence,
        )
        self.assertFalse(adapter_result.has_errors)
        self.assertFalse(hasattr(adapter_result, "modules"))

    def test_translates_diagnostics_and_preserves_source_location(self) -> None:
        result = self.adapter.parse(
            IaCInput(
                (
                    IaCDocument(
                        "broken.tf",
                        'resource "aws_s3_bucket" "broken" {',
                    ),
                )
            )
        )

        self.assertTrue(result.has_errors)
        self.assertEqual(
            result.diagnostics[0].severity,
            IaCDiagnosticSeverity.ERROR,
        )
        self.assertIn("broken.tf:", result.diagnostics[0].source_location)
        self.assertEqual(result.diagnostics[0].adapter_id, "terraform-hcl")

    def test_combines_documents_deterministically_without_cross_file_inference(
        self,
    ) -> None:
        bucket = IaCDocument(
            "bucket.tf",
            'resource "aws_s3_bucket" "logs" {}',
        )
        policy = IaCDocument(
            "policy.tf",
            '''
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
}
''',
        )

        first = self.adapter.parse(IaCInput((policy, bucket)))
        second = self.adapter.parse(IaCInput((bucket, policy)))

        self.assertEqual(first.architecture, second.architecture)
        self.assertEqual(first.declared_evidence, second.declared_evidence)
        self.assertEqual(len(first.architecture.resources), 2)
        self.assertEqual(len(first.declared_evidence), 2)
        self.assertEqual(first.architecture.relationships, ())
        policy_resource = next(
            item
            for item in first.architecture.resources
            if item.resource_type == "aws_s3_bucket_policy"
        )
        self.assertEqual(
            policy_resource.properties["_cloudguard"][
                "unresolved_dependencies"
            ],
            ("aws_s3_bucket.logs",),
        )

    def test_duplicate_resource_identity_is_an_explicit_error(self) -> None:
        first = IaCDocument(
            "a.tf",
            'resource "aws_s3_bucket" "logs" {}',
        )
        second = IaCDocument(
            "b.tf",
            'resource "aws_s3_bucket" "logs" {}',
        )

        result = self.adapter.parse(IaCInput((first, second)))

        self.assertTrue(result.has_errors)
        self.assertEqual(len(result.architecture.resources), 1)
        self.assertTrue(
            any(
                "duplicate resource identity" in item.message
                for item in result.diagnostics
            )
        )


if __name__ == "__main__":
    unittest.main()

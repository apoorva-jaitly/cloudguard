import tempfile
import unittest
from pathlib import Path

from cloudguard.domain import RelationshipType
from cloudguard.terraform import DiagnosticSeverity, TerraformParser

FIXTURES = Path(__file__).parent / "fixtures" / "terraform"


class TerraformParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = TerraformParser()

    def test_parses_resources_attributes_dependencies_and_module(self) -> None:
        result = self.parser.parse_file(FIXTURES / "good" / "main.tf")

        self.assertFalse(result.has_errors)
        self.assertEqual(len(result.architecture.resources), 3)
        resources = {resource.id: resource for resource in result.architecture.resources}
        bucket = resources["terraform.aws_s3_bucket.logs"]
        policy = resources["terraform.aws_s3_bucket_policy.logs"]

        self.assertEqual(bucket.resource_type, "aws_s3_bucket")
        self.assertEqual(bucket.name, "logs")
        self.assertEqual(bucket.properties["bucket"], "example-production-logs")
        self.assertIn("main.tf:17:1-", bucket.source_location)
        self.assertIn("attribute_sources", bucket.properties["_cloudguard"])
        self.assertEqual(
            policy.properties["_cloudguard"]["dependencies"],
            ("aws_iam_role.writer", "aws_s3_bucket.logs"),
        )

        relationships = {
            (
                relationship.source_resource_id,
                relationship.target_resource_id,
                relationship.relationship_type,
            )
            for relationship in result.architecture.relationships
        }
        self.assertIn(
            (
                "terraform.aws_s3_bucket_policy.logs",
                "terraform.aws_s3_bucket.logs",
                RelationshipType.DEPENDS_ON,
            ),
            relationships,
        )
        self.assertIn(
            (
                "terraform.aws_s3_bucket_policy.logs",
                "terraform.aws_iam_role.writer",
                RelationshipType.DEPENDS_ON,
            ),
            relationships,
        )

        self.assertEqual(len(result.modules), 1)
        self.assertEqual(result.modules[0].name, "network")
        self.assertEqual(result.modules[0].source, "./modules/network")
        self.assertEqual(result.modules[0].version, "1.2.3")

    def test_preserves_complex_expression_source(self) -> None:
        result = self.parser.parse_file(FIXTURES / "good" / "main.tf")
        policy = next(
            resource
            for resource in result.architecture.resources
            if resource.resource_type == "aws_s3_bucket_policy"
        )

        expression = policy.properties["policy"]["expression"]
        self.assertIn("jsonencode", expression)
        self.assertIn("aws_iam_role.writer.arn", expression)

    def test_preserves_nested_blocks_for_deterministic_rules(self) -> None:
        result = self.parser.parse_text(
            '''
resource "aws_ecs_service" "api" {
  name = "api"
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
}
''',
            filename="service.tf",
        )

        service = result.architecture.resources[0]
        block = service.properties["_blocks"][0]
        self.assertEqual(block["type"], "deployment_circuit_breaker")
        self.assertTrue(block["attributes"]["rollback"])

    def test_emits_evidence_with_source_locations(self) -> None:
        result = self.parser.parse_file(FIXTURES / "good" / "main.tf")

        self.assertGreaterEqual(len(result.evidence), 5)
        self.assertTrue(all(":1" in item.source or ".tf:" in item.source for item in result.evidence))
        relationship_evidence_ids = {
            evidence_id
            for relationship in result.architecture.relationships
            for evidence_id in relationship.evidence_ids
        }
        self.assertTrue(relationship_evidence_ids)
        self.assertTrue(
            relationship_evidence_ids.issubset(
                {evidence.id for evidence in result.evidence}
            )
        )

    def test_malformed_files_return_diagnostics_without_raising(self) -> None:
        for fixture in (FIXTURES / "broken").glob("*.tf"):
            with self.subTest(fixture=fixture.name):
                result = self.parser.parse_file(fixture)
                self.assertTrue(result.has_errors)
                self.assertTrue(
                    any(
                        diagnostic.severity is DiagnosticSeverity.ERROR
                        for diagnostic in result.diagnostics
                    )
                )

    def test_rejects_oversized_input(self) -> None:
        parser = TerraformParser(max_input_bytes=20)
        result = parser.parse_text(
            'resource "aws_s3_bucket" "logs" {}', filename="large.tf"
        )

        self.assertTrue(result.has_errors)
        self.assertIn("exceeds 20 bytes", result.diagnostics[0].message)
        self.assertEqual(result.architecture.resources, ())

    def test_rejects_symlink_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.tf"
            target.write_text('resource "aws_s3_bucket" "logs" {}', encoding="utf-8")
            link = root / "link.tf"
            link.symlink_to(target)

            result = self.parser.parse_file(link)

        self.assertTrue(result.has_errors)
        self.assertIn("symbolic links", result.diagnostics[0].message)

    def test_allowed_root_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            allowed.mkdir()
            outside = root / "outside.tf"
            outside.write_text(
                'resource "aws_s3_bucket" "outside" {}',
                encoding="utf-8",
            )
            parser = TerraformParser(allowed_root=allowed)

            result = parser.parse_file(outside)

        self.assertTrue(result.has_errors)
        self.assertIn("outside the configured allowed root", result.diagnostics[0].message)

    def test_does_not_execute_function_like_input(self) -> None:
        marker = Path(tempfile.gettempdir()) / "cloudguard-parser-must-not-create"
        marker.unlink(missing_ok=True)
        source = f'''
resource "aws_s3_bucket" "logs" {{
  bucket = file("{marker}")
}}
'''

        result = self.parser.parse_text(source, filename="hostile.tf")

        self.assertFalse(marker.exists())
        resource = result.architecture.resources[0]
        self.assertIn("file(", resource.properties["bucket"]["expression"])


if __name__ == "__main__":
    unittest.main()

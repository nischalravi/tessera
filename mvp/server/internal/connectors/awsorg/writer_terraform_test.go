package awsorg

import (
	"os"
	"testing"
)

// The Terraform module's policy is the one Tessera defines: the file is generated from WriterPolicy, so what a
// customer applies is what CheckWriterPolicy and the writer tests hold to the contract. To regenerate it after
// changing WriterPolicy:
//
//	TESSERA_UPDATE_WRITER_POLICY=1 go test ./internal/connectors/awsorg -run TestWriterPolicyIsTheTerraformModulesPolicy
func TestWriterPolicyIsTheTerraformModulesPolicy(t *testing.T) {
	const path = "../../../../../deploy/terraform/aws-writer-role/writer-policy.json"
	want := append(WriterPolicy(), '\n')
	if os.Getenv("TESSERA_UPDATE_WRITER_POLICY") == "1" {
		if err := os.WriteFile(path, want, 0o644); err != nil { // #nosec G306 -- a public policy document
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Error("deploy/terraform/aws-writer-role/writer-policy.json differs from WriterPolicy(): regenerate it (see this test)")
	}
	if err := CheckWriterPolicy(got); err != nil {
		t.Error(err)
	}
}

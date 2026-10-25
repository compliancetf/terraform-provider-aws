package main

import "github.com/hashicorp/terraform-plugin-go/tfprotov5"

// Protocol 5 has no state stores; v6/statestore.go advertises fake_store.

func withStateStoreMetadata(r *tfprotov5.GetMetadataResponse) *tfprotov5.GetMetadataResponse {
	return r
}

func withStateStoreSchema(r *tfprotov5.GetProviderSchemaResponse) *tfprotov5.GetProviderSchemaResponse {
	return r
}

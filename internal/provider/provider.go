// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure NatsNkeyProvider satisfies various provider interfaces.
var _ provider.Provider = &NatsNkeyProvider{}
var _ provider.ProviderWithFunctions = &NatsNkeyProvider{}
var _ provider.ProviderWithEphemeralResources = &NatsNkeyProvider{}

// NatsNkeyProvider defines the provider implementation.
type NatsNkeyProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// NatsNkeyProviderModel describes the provider data model.
type NatsNkeyProviderModel struct {
}

func (p *NatsNkeyProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "nkey"
	resp.Version = p.version
}

func (p *NatsNkeyProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

func (p *NatsNkeyProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data NatsNkeyProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

}

func (p *NatsNkeyProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewNkey,
	}
}

func (p *NatsNkeyProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *NatsNkeyProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func (p *NatsNkeyProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		NewNkeyEphemeral,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &NatsNkeyProvider{
			version: version,
		}
	}
}

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/nats-io/nkeys"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ ephemeral.EphemeralResource = &NkeyEphemeral{}

func NewNkeyEphemeral() ephemeral.EphemeralResource {
	return &NkeyEphemeral{}
}

// NkeyEphemeral defines the ephemeral resource implementation.
type NkeyEphemeral struct {
}

// NkeyEphemeralModel describes the ephemeral resource data model.
type NkeyEphemeralModel struct {
	KeyType    types.String `tfsdk:"type"`
	PublicKey  types.String `tfsdk:"public_key"`
	PrivateKey types.String `tfsdk:"private_key"`
	Seed       types.String `tfsdk:"seed"`
}

func (r *NkeyEphemeral) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_nkey"
}

func (r *NkeyEphemeral) Schema(ctx context.Context, req ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "An ephemeral nkey is an ed25519 key pair formatted for use with NATS. The key pair is generated during plan/apply and is not persisted to state.",

		Attributes: map[string]schema.Attribute{
			"type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The type of nkey to generate. Must be one of user|account|server|cluster|operator|curve",
			},
			"public_key": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Public key of the nkey to be given in config to the nats server",
			},
			"private_key": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Private key of the nkey to be given to the client for authentication",
				Sensitive:           true,
			},
			"seed": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Seed of the nkey to be given to the client for authentication",
				Sensitive:           true,
			},
		},
	}
}

func (r *NkeyEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data NkeyEphemeralModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if err := data.generateKeys(); err != nil {
		resp.Diagnostics.AddError("generating nkey", err.Error())
		return
	}
	tflog.Trace(ctx, "opened ephemeral nkey resource")

	// Save data into Terraform ephemeral result
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *NkeyEphemeral) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	// No cleanup needed for nkeys as they are just generated values
	tflog.Trace(ctx, "closed ephemeral nkey resource")
}

func (m *NkeyEphemeralModel) generateKeys() (err error) {
	var keys nkeys.KeyPair

	switch strings.ToLower(m.KeyType.ValueString()) {
	case "user":
		keys, err = nkeys.CreateUser()
	case "account":
		keys, err = nkeys.CreateAccount()
	case "server":
		keys, err = nkeys.CreateServer()
	case "cluster":
		keys, err = nkeys.CreateCluster()
	case "operator":
		keys, err = nkeys.CreateOperator()
	case "curve":
		keys, err = nkeys.CreateCurveKeys()
	default:
		keys, err = nkeys.CreateAccount()
	}
	if err != nil {
		return err
	}

	pubKey, err := keys.PublicKey()
	if err != nil {
		return err
	}
	privKey, err := keys.PrivateKey()
	if err != nil {
		return err
	}
	seed, err := keys.Seed()
	if err != nil {
		return err
	}

	m.PublicKey = types.StringValue(pubKey)
	m.PrivateKey = types.StringValue(string(privKey))
	m.Seed = types.StringValue(string(seed))

	return nil
}

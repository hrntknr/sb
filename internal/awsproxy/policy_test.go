package awsproxy

import "testing"

func TestReadOnlyAccessServicePermissions(t *testing.T) {
	for _, tt := range []struct {
		service, action string
		want            bool
	}{
		{"ec2", "ec2:DescribeTransitGatewayAttachments", true},
		{"ec2", "ec2:SearchTransitGatewayRoutes", true},
		{"ec2", "ec2:CreateVpc", false},
		{"dynamodb", "dynamodb:BatchGetItem", true},
		{"dynamodb", "dynamodb:ExecuteStatement", false}, // PartiQL write actions are not all read-only, so `ro` rejects it.
		{"dynamodb", "dynamodb:DescribeTable", false},    // Requires the replication actions, not all read-only.
		{"dynamodb", "dynamodb:PartiQLSelect", false},
		{"dynamodb", "dynamodb:SearchVectors", false}, // No operation mapping in AWS's reference yet.
		{"dynamodb", "dynamodb:TransactWriteItems", false},
		{"logs", "logs:StartQuery", false},    // FilterLogEvents or Unmask are not read-only actions.
		{"logs", "logs:StartLiveTail", false}, // No operation mapping in AWS's reference yet.
		{"logs", "logs:PutRetentionPolicy", false},
		{"sts", "sts:GetAccessKeyInfo", true},
		{"athena", "athena:GetSessionEndpoint", true},
		{"cognito-identity", "cognito-identity:GetCredentialsForIdentity", true},
		{"cognito-identity", "cognito-identity:GetOpenIdToken", true},
		{"cognito-identity", "cognito-identity:GetOpenIdTokenForDeveloperIdentity", true},
		{"cognito-idp", "cognito-idp:DescribeUserPoolClient", true},
		{"cognito-idp", "cognito-idp:GetTokensFromRefreshToken", true},
		{"devicefarm", "devicefarm:GetRemoteAccessSession", true},
		{"devicefarm", "devicefarm:ListRemoteAccessSessions", true},
		{"ecr", "ecr:GetAuthorizationToken", true},
		{"ecr-public", "ecr-public:GetAuthorizationToken", true},
		{"license-manager", "license-manager:GetAccessToken", true},
		{"ssm", "ssm:GetAccessToken", true},
		{"storagegateway", "storagegateway:DescribeChapCredentials", true},
		{"sts", "sts:GetSessionToken", true},
		{"sts", "sts:AssumeRole", false},
		{"kinesis", "kinesis:ListStreams", true},
		{"kinesis", "kinesis:CreateStream", false},
		{"kinesis", "kinesis:UnknownOperation", false},
	} {
		t.Run(tt.action, func(t *testing.T) {
			targets := []Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: tt.service, Mode: "ro"}}}}
			if got := allows(targets, "dev", "us-east-1", tt.action); got != tt.want {
				t.Errorf("ro allows(%s) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestReadWriteAllowsAllActionsWithinService(t *testing.T) {
	targets := []Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: "dynamodb", Mode: "rw"}}, Regions: []string{"us-*"}}}
	for _, action := range []string{"dynamodb:GetItem", "dynamodb:TransactWriteItems", "dynamodb:CreateGlobalTable"} {
		if !allows(targets, "dev", "us-east-1", action) {
			t.Errorf("rw must permit %s", action)
		}
	}
	for _, action := range []string{"s3:DeleteObject", "dynamodb:", "dynamodb:DeleteItem"} {
		region := "us-east-1"
		if action == "dynamodb:DeleteItem" {
			region = "eu-west-1"
		}
		if allows(targets, "dev", region, action) {
			t.Errorf("rw must reject %s in %s", action, region)
		}
	}
	role, err := assumedRole(targets, "dev")
	if err != nil || role != "arn:aws:iam::123456789012:role/dev" {
		t.Errorf("assumedRole = %q, err = %v", role, err)
	}
	if role, err := assumedRole([]Target{{Profile: "dev"}}, "dev"); err != nil || role != "" {
		t.Errorf("omitted roleArn assumedRole = %q, err = %v", role, err)
	}
	_, err = assumedRole([]Target{
		{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev"},
		{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/other"},
	}, "dev")
	if err == nil {
		t.Error("conflicting roles must error")
	}
}

func TestReadWriteAllowsCredentialIssuingOperations(t *testing.T) {
	targets := []Target{{Profile: "dev", Services: []Service{{Name: "ecr", Mode: "rw"}}}}
	if !allows(targets, "dev", "us-east-1", "ecr:GetAuthorizationToken") {
		t.Fatal("rw must permit credential-issuing operations")
	}
}

// TestAssumedRoleRulesAreOrderIndependent covers the duplicate rules: an
// omitted roleArn is one selection, so rules matching one profile — a
// wildcard and an individual name — agree only when all omit it or all
// set the same one, whatever their order.
func TestAssumedRoleRulesAreOrderIndependent(t *testing.T) {
	const (
		roleA = "arn:aws:iam::123456789012:role/a"
		roleB = "arn:aws:iam::123456789012:role/b"
	)
	for _, tt := range []struct {
		name     string
		targets  []Target
		wantErr  bool
		wantRole string
	}{
		{name: "agree on the same roleArn", wantRole: roleA, targets: []Target{
			{Profile: "dev", RoleARN: roleA}, {Profile: "*", RoleARN: roleA}}},
		{name: "agree on omitting it", wantRole: "", targets: []Target{
			{Profile: "dev"}, {Profile: "*"}}},
		{name: "a roleArn mixed with an omission", wantErr: true, targets: []Target{
			{Profile: "dev", RoleARN: roleA}, {Profile: "*"}}},
		{name: "an omission mixed with a roleArn", wantErr: true, targets: []Target{
			{Profile: "*"}, {Profile: "dev", RoleARN: roleA}}},
		{name: "different roleArn values", wantErr: true, targets: []Target{
			{Profile: "dev", RoleARN: roleA}, {Profile: "*", RoleARN: roleB}}},
		{name: "different roleArn values reversed", wantErr: true, targets: []Target{
			{Profile: "*", RoleARN: roleB}, {Profile: "dev", RoleARN: roleA}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			role, err := assumedRole(tt.targets, "dev")
			switch {
			case tt.wantErr && err == nil:
				t.Fatalf("assumedRole(%v) = %q, want a conflict", tt.targets, role)
			case tt.wantErr:
			case err != nil:
				t.Fatalf("assumedRole(%v) = %v, want %q", tt.targets, err, tt.wantRole)
			case role != tt.wantRole:
				t.Fatalf("assumedRole(%v) = %q, want %q", tt.targets, role, tt.wantRole)
			}
		})
	}
}

// TestAgreeingRulesMergePermissionsAsUnion covers agreeing rules: when
// every rule matching a profile agrees on the role, the permissions are
// the union of the grants — one rule's regions and services do not
// remove the other's.
func TestAgreeingRulesMergePermissionsAsUnion(t *testing.T) {
	targets := []Target{
		{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Regions: []string{"eu-*"}, Services: []Service{{Name: "dynamodb", Mode: "ro"}}},
		{Profile: "*", RoleARN: "arn:aws:iam::123456789012:role/dev", Regions: []string{"us-*"}, Services: []Service{{Name: "ec2", Mode: "rw"}}},
	}
	for _, tt := range []struct {
		region, action string
		want           bool
	}{
		{"eu-west-1", "dynamodb:GetItem", true},        // the individual rule: ro in eu-*
		{"us-east-1", "ec2:TerminateInstances", true},  // the wildcard rule: rw in us-*
		{"us-east-1", "dynamodb:GetItem", false},       // the individual rule's region does not match
		{"eu-west-1", "ec2:TerminateInstances", false}, // the wildcard rule's region does not match
	} {
		if got := allows(targets, "dev", tt.region, tt.action); got != tt.want {
			t.Errorf("allows(%s, %s) = %v, want %v", tt.region, tt.action, got, tt.want)
		}
	}
}

func TestReadOnlyOperationsAllowList(t *testing.T) {
	// The embedded list must agree with the per-request `ro` verdicts: allowed
	// operations are members, everything else (writes, unknown operations,
	// operations without an action mapping) is not.
	for _, tt := range []struct {
		service, operation string
		want               bool
	}{
		{"kinesis", "liststreams", true},
		{"kinesis", "createstream", false},
		{"kinesis", "unknownoperation", false},
		{"dynamodb", "getitem", true},
		{"dynamodb", "putitem", false},
		{"dynamodb", "executestatement", false}, // PartiQL write actions are not all read-only.
		{"dynamodb", "transactwriteitems", false},
	} {
		if got := allowedOperations[tt.service][tt.operation]; got != tt.want {
			t.Errorf("allowedOperations[%s][%s] = %v, want %v", tt.service, tt.operation, got, tt.want)
		}
	}
}

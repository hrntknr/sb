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
		{"dynamodb", "dynamodb:ExecuteStatement", false}, // PartiQL write actions are not all read-only, so `r` rejects it.
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
			targets := []Target{{Profile: "dev", RoleARN: "arn:aws:iam::123456789012:role/dev", Services: []Service{{Name: tt.service, Mode: "r"}}}}
			if got := allows(targets, "dev", "us-east-1", tt.action); got != tt.want {
				t.Errorf("r allows(%s) = %v, want %v", tt.action, got, tt.want)
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

func TestReadOnlyOperationsAllowList(t *testing.T) {
	// The embedded list must agree with the per-request `r` verdicts: allowed
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

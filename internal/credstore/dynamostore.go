package credstore

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const attrAccessKeyID = "AccessKeyId"

// dynamoStore is a Store backed by a DynamoDB table, keyed by access key ID.
// This mirrors how AWS's own control-plane services keep identity metadata: a
// single-table key-value lookup, not a relational join. The Store interface is
// unchanged — only the guts behind Put/Lookup moved out of the process.
type dynamoStore struct {
	client *dynamodb.Client
	table  string
}

// OpenDynamo returns a Store backed by the DynamoDB table, creating the table
// if it does not yet exist. endpoint points at a DynamoDB — e.g. DynamoDB Local
// at http://dynamodb:8000. A region and credentials are required by the SDK;
// DynamoDB Local accepts any values, so static placeholders are fine.
func OpenDynamo(ctx context.Context, endpoint, region, table string) (Store, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("mincloud", "mincloud", ""),
		),
	)
	if err != nil {
		return nil, err
	}
	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})

	s := &dynamoStore{client: client, table: table}
	if err := s.ensureTable(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// ensureTable creates the credentials table on first run and waits for it to
// become ACTIVE, so the very first Put cannot race table creation.
func (s *dynamoStore) ensureTable(ctx context.Context) error {
	_, err := s.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &s.table})
	if err == nil {
		return nil
	}
	var notFound *types.ResourceNotFoundException
	if !errors.As(err, &notFound) {
		return err
	}

	if _, err := s.client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   &s.table,
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String(attrAccessKeyID), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String(attrAccessKeyID), KeyType: types.KeyTypeHash},
		},
	}); err != nil {
		return err
	}
	return dynamodb.NewTableExistsWaiter(s.client).
		Wait(ctx, &dynamodb.DescribeTableInput{TableName: &s.table}, 30*time.Second)
}

func (s *dynamoStore) Put(accessKeyID string, c Credential) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.table,
		Item: map[string]types.AttributeValue{
			attrAccessKeyID:   &types.AttributeValueMemberS{Value: accessKeyID},
			"SecretAccessKey": &types.AttributeValueMemberS{Value: c.SecretAccessKey},
			"Account":         &types.AttributeValueMemberS{Value: c.Identity.Account},
			"UserId":          &types.AttributeValueMemberS{Value: c.Identity.UserID},
			"Arn":             &types.AttributeValueMemberS{Value: c.Identity.ARN},
		},
	})
	if err != nil {
		// A durable store that silently drops writes is worse than a loud one:
		// the operator must know persistence is broken.
		panic("credstore: PutItem failed: " + err.Error())
	}
}

func (s *dynamoStore) Lookup(accessKeyID string) (Credential, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.table,
		Key: map[string]types.AttributeValue{
			attrAccessKeyID: &types.AttributeValueMemberS{Value: accessKeyID},
		},
	})
	if err != nil {
		// Fail closed: on a store error, reject rather than risk authorizing
		// against data we could not read. Log loudly so it is visible.
		log.Printf("credstore: GetItem failed for %s: %v", accessKeyID, err)
		return Credential{}, false
	}
	if out.Item == nil {
		return Credential{}, false
	}
	return Credential{
		SecretAccessKey: stringAttr(out.Item, "SecretAccessKey"),
		Identity: Identity{
			Account: stringAttr(out.Item, "Account"),
			UserID:  stringAttr(out.Item, "UserId"),
			ARN:     stringAttr(out.Item, "Arn"),
		},
	}, true
}

func stringAttr(item map[string]types.AttributeValue, name string) string {
	if v, ok := item[name].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

package inference

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/credentials/insecure"

	torchserve "github.com/google/syzkaller/pkg/inference/torchserve"
)


type Connector struct {
	serverAddr string
	authkey    string
	client     torchserve.InferenceAPIsServiceClient
	ctx        context.Context
}

func InitConnect(addr, key string) *Connector {
	var ctx context.Context

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("cannot connect: %v", err)
	}
	ctx = context.Background()
	if key != "" {
		md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %v", key))
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	c := torchserve.NewInferenceAPIsServiceClient(conn)
	return &Connector{
		serverAddr: addr,
		authkey:    key,
		client:     c,
		ctx:        ctx,
	}
}

func (connector *Connector) Predict(input map[string][]byte) ([]int, error) {
	var progNodeIdxList []int

	req := &torchserve.PredictionsRequest{
		ModelName:    "PMModel",
		ModelVersion: "0.1",
		Input:        input,
	}

	res, err := connector.client.Predictions(connector.ctx, req)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(res.Prediction, &progNodeIdxList)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling json: %v", err)
	}
	return progNodeIdxList, err
}

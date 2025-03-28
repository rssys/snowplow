package inference

import (
	"flag"
	"fmt"
	"log"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

var (
	addr = flag.String("addr", "localhost:7070", "torchserve address")
	authKey = flag.String("key", "", "torchserve auth key")
)

// ReadFileToByteSlice reads the content of the file at the given path and returns it as a byte slice.
// created by gpt
func ReadFileToByteSlice(filePath string) ([]byte, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read the file content into a byte slice
	content, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return content, nil
}

var dataDirpath = "/graphdataset/dataset/"
var baseProgHashList = []string{
	"d7e2a8cd41dad51cc04f4dc7c6b8d3319125927c-snow-profiler-kernel68-collection-europe-west4-f5mc",
	"7d97ec1c666efd4780c186247028f6f97f8dd426-snow-profiler-kernel68-collection-europe-west2-qm39",
	"83586dc374b9d83cb1d765d9fec123546cd56d1a-snow-profiler-kernel68-collection-europe-west2-fqdr",
	"be09ee39b4cd6a1d064536fae4f7870936bb888a-snow-profiler-kernel68-collection-europe-west2-f2qb",
	"b980b6e8969bce7cafbb4f1b3616bdabf804bd44-snow-profiler-kernel68-collection-us-east4-jp17",
	"bb7067f93e9e09d31cb1da32f5f291ce61b2595b-snow-profiler-kernel68-collection-europe-west2-bm6r",
	"50d3320d131fccf9c410cacc4452d16e7208c1d4-snow-profiler-kernel68-collection-europe-west3-78q3",
	"ecb10b080f36137d683f17cecc52c1752671272b-snow-profiler-kernel68-collection-us-west2-br7s",
}
var urbNodeIdxList = []string{
	"2195",
	"1833",
	"3583",
	"8266",
	"2980",
	"2083",
	"6215",
	"2871",
}

func loadGraphData(idx int) map[string][]byte {
	input := make(map[string][]byte)

	graphDataDirpath := path.Join(dataDirpath, baseProgHashList[idx])
	data, _ := ReadFileToByteSlice(path.Join(graphDataDirpath, "cover.node.csv"))
	input["cover.node"] = data
	data, _ = ReadFileToByteSlice(path.Join(graphDataDirpath, "cover.edge.csv"))
	input["cover.edge"] = data
	data, _ = ReadFileToByteSlice(path.Join(graphDataDirpath, "prog.node.csv"))
	input["prog.node"] = data
	data, _ = ReadFileToByteSlice(path.Join(graphDataDirpath, "prog.edge.csv"))
	input["prog.edge"] = data
	data, _ = ReadFileToByteSlice(path.Join(graphDataDirpath, "connect.edge.csv"))
	input["fuseedge.edge"] = data
	input["urbNodeIdx"] = []byte(urbNodeIdxList[idx])

	input["threshold"] = []byte(fmt.Sprintf("%f", 0.82))

	return input
}

func TestInference(t *testing.T) {
	flag.Parse()

	connector := InitConnect(*addr, *authKey)
	for i := 0; i < len(urbNodeIdxList); i++ {
		input := loadGraphData(i)
		prediction, _ := connector.Predict(input)
		log.Printf("%v", prediction)
	}
}

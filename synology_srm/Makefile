# 二进制文件名称
BINARY_NAME := synology_srm

build-linux-amd64:
	@echo "打包 Linux （amd64架构） 版本"
	GOOS=linux GOARCH=amd64 go build -o ./synology_srm .

build-linux-arm64:
	@echo "打包 Linux （arm64架构） 版本"
	GOOS=linux GOARCH=amd64 go build -o ./synology_srm .
#!/bin/bash

# 设置输出目录
OUTPUT_DIR="build"
TMP_DIR="/tmp/sshpiperd_extract"
PACKAGE_NAME="sshmux_installer.run"
SSHPIPERD_URL="https://github.com/tg123/sshpiper/releases/download/v1.3.1/sshpiperd_with_plugins_linux_x86_64.tar.gz"
SSHPIPERD_TAR="sshpiperd_with_plugins_linux_x86_64.tar.gz"

rm -rf $OUTPUT_DIR

# 创建输出目录
mkdir -p $OUTPUT_DIR
mkdir -p $TMP_DIR

# 设置 GOOS 和 GOARCH 为 Linux x86_64
export GOOS=linux
export GOARCH=amd64

# 下载 sshpiperd_with_plugins
echo "Downloading sshpiperd_with_plugins..."
curl -L $SSHPIPERD_URL -o $TMP_DIR/$SSHPIPERD_TAR

# 解压 sshpiperd_with_plugins 到 /tmp
echo "Extracting sshpiperd_with_plugins to /tmp..."
tar -xzvf $TMP_DIR/$SSHPIPERD_TAR -C $TMP_DIR

# 只将 sshpiperd 文件复制到输出目录
echo "Copying sshpiperd to output directory..."
cp $TMP_DIR/sshpiperd $OUTPUT_DIR/sshpiperd

# 清理临时文件
rm -rf $TMP_DIR

# 交叉编译 sshpiper-plugin
echo "Building sshpiper-plugin for Linux x86_64..."
cd sshpiper-plugin
go build -o "../$OUTPUT_DIR/sshpiper-plugin"
cd ..

# 交叉编译 web
echo "Building sshmux-web for Linux x86_64..."
cd web
go build -o "../$OUTPUT_DIR/sshmux-web"
cd ..

# 复制 systemd unit 文件
echo "Copying systemd unit files..."
cp scripts/systemd/sshpiper.service $OUTPUT_DIR/
cp scripts/systemd/sshmux-web.service $OUTPUT_DIR/

# 复制安装脚本
echo "Copying installer script..."
cp scripts/install.sh $OUTPUT_DIR/
chmod +x $OUTPUT_DIR/install.sh

# 使用 makeself 打包二进制文件和 systemd unit 文件
echo "Creating self-extracting archive using makeself..."
makeself $OUTPUT_DIR $PACKAGE_NAME "sshmux installer" ./install.sh

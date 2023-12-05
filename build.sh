#!/bin/bash

# 不在项目中编译了(依赖有冲突？:clang版本)
# 直接使用编译好的第三方库socket_hook_py-0.1.0-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl 

yum install clang
git clone git@dev.shuimuyulin.com:contrib/socket_hook_py.git
git clone git@dev.shuimuyulin.com:contrib/wifi-client.git

COMPONENT_PYTHON3_PYPI_MIRROR=https://pypi.tuna.tsinghua.edu.cn/simple
COMPONENT_PYTHON3_PATH=/mnt/sdb/peter/project/wingfuzz-tool-protocol/build/install/usr/lib/wingfuzz-protocol/components/python3/

${COMPONENT_PYTHON3_PATH}/bin/python3 -m pip install -i ${COMPONENT_PYTHON3_PYPI_MIRROR} maturin 
${COMPONENT_PYTHON3_PATH}/bin/python3 -m pip install -i ${COMPONENT_PYTHON3_PYPI_MIRROR} -r ./wifi-client/requirements.txt --target=./site-packages
(
  export PATH=${COMPONENT_PYTHON3_PATH}/bin/:${PATH}
  cd socket_hook_py
  ${COMPONENT_PYTHON3_PATH}/bin/maturin build --release --out ../tmp/
)
${COMPONENT_PYTHON3_PATH}/bin/python3 -m pip install ./tmp/socket_hook_py-* --target=./site-packages
exit 0

set -x
CURRENT=$(cd $(dirname ${BASH_SOURCE[0]}) && pwd)
echo ${CURRENT}
PYTHON3=${PYTHON3:-python3}
if [ -n "${WIFI_VENV}" ]; then 
    MATURIN="${WIFI_VENV}/maturin"
    export PATH=${WIFI_VENV}:${PATH}
else
    MATURIN=maturin
fi 

if [ -n "${COMPONENT_PYTHON3_PYPI_MIRROR}" ]; then
    PIP3_INSTALL="${PYTHON3} -m pip install -i ${COMPONENT_PYTHON3_PYPI_MIRROR}"
else
    PIP3_INSTALL="${PYTHON3} -m pip install "
fi

${PIP3_INSTALL} -r ./requirements.txt 
cd ${CURRENT}/submodule/socket_hook_py.git &&
    ${PIP3_INSTALL} maturin && 
    rm ./tmp/* -rf &&
    ${MATURIN} build --release --out ./tmp &&
    ${PIP3_INSTALL} ./tmp/socket_hook_py-*

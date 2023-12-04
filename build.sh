#!/bin/bash

不在项目中编译了(依赖有冲突？:clang版本)
直接使用编译好的第三方库socket_hook_py-0.1.0-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl 
# ${BASE_PATH}/wingfuzz-tool-protocol/build/build/components/python3/install/python/install/bin/python3 -m pip install maturin
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
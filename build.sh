#!/bin/bash

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
    PYTHON3="${PYTHON3} -i ${COMPONENT_PYTHON3_PYPI_MIRROR}"
fi

${PYTHON3} -m pip install -r ./requirements.txt 
cd ${CURRENT}/submodule/socket_hook_py.git &&
    ${PYTHON3} -m pip install maturin && 
    rm ./tmp/* -rf &&
    ${MATURIN} build --release --out ./tmp &&
    ${PYTHON3} -m pip install ./tmp/socket_hook_py-*
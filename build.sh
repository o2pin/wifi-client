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
    PIP3="${PYTHON3} -m pip -i ${COMPONENT_PYTHON3_PYPI_MIRROR}"
else
    PIP3="${PYTHON3} -m pip "
fi

${PIP3} install -r ./requirements.txt 
cd ${CURRENT}/submodule/socket_hook_py.git &&
    ${PIP3} install maturin && 
    rm ./tmp/* -rf &&
    ${MATURIN} build --release --out ./tmp &&
    ${PIP3} install ./tmp/socket_hook_py-*
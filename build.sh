#!/bin/bash
CURRENT=$(cd $(dirname ${BASH_SOURCE[0]}) && pwd)
PYTHON3=${PYTHON3:-python3}
set -x
if [ -n "${COMPONENT_PYTHON3_PYPI_MIRROR}" ]; then
    ${PYTHON3} -m pip install -i ${COMPONENT_PYTHON3_PYPI_MIRROR} -r ./requirements.txt 
    cd ${CURRENT}/submodule/socket_hook_py.git &&
        ${PYTHON3} -m pip install -i ${COMPONENT_PYTHON3_PYPI_MIRROR} maturin && 
        maturin develop --release
else
    ${PYTHON3} -m pip install -r ./requirements.txt 
    cd ${CURRENT}/submodule/socket_hook_py.git &&
        ${PYTHON3} -m pip install maturin && 
        maturin develop --release
fi
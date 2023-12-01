#!/bin/bash
CURRENT=$(cd $(dirname ${BASH_SOURCE[0]}) && pwd)
PYTHON3=${PYTHON3:-python3}

cd ${CURRENT}/submodule/socket_hook_py.git &&
    ${PYTHON3} -m pip install maturin && 
    maturin develop --release

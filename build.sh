#!/bin/bash

cd submodule/socket_hook_py.git &&
    PYTHON3={PYTHON3:-python3} &&
    ${PYTHON3} -m pip install maturin && 
    maturin develop --release &&

"""
Module that takes care of executing input/scripts by injecting them inside the interpreter

IMPORTANT NOTE:
    This module is NOT executing any potentially malicious code, e.g. the one being scanned by aura.
    It is intended to inject helper scripts that parse AST information or other kind of info from the source code.
    This allows aura to process both Py2k and Py3k source code as it injects the parsers into the appropriate
    interpreter that is able to parse the target source code.
"""

import os
import sys
import subprocess
from shutil import which
from typing import List, Optional, Callable

from . import config
from .analyzers import python_src_inspector
from .json_proxy import loads, JSONDecodeError
from .exceptions import PythonExecutorError


LOGGER = config.get_logger(__name__)
NATIVE_ENVIRONMENT_CACHE = None


def run_with_interpreters(*, metadata=None, **kwargs):
    """
    Proxy to execute_interpreter
    Iterates over defined interpreter until one that runs the input/script is found

    Return a 3-tuple with the following elements:
    - JSON decoded output of the executed script
    - name of the interpreter as defined in aura config
    - path/command to the interpreter as defined in aura config

    In case an interpreter that is able to execute the input script was not found, all tuple elements are set to None
    """
    if metadata and metadata.get("interpreter_path"):
        return execute_interpreter(
            interpreter=metadata["interpreter_path"],
            **kwargs
        )

    executor_exception = None

    for name, interpreter in get_interpreters().items():
        try:
            output = execute_interpreter(interpreter=interpreter, **kwargs)
            if output is not None:
                if metadata is not None:
                    metadata["interpreter_name"] = name
                    metadata["interpreter_path"] = interpreter

                return output
        except PythonExecutorError as exc:
            executor_exception = exc
            continue

    if executor_exception is not None:
        raise executor_exception


def get_interpreters() -> dict:
    """
    Iterate over configured interpreters and filter out those that are not available on the system
    By default Aura has both py2k and py3k configured, if py2k is not present on the system, this will filter it out
    :return: dict of filtered interpreters with only items/paths that exists on the system
    """
    valid = {}

    interpreters = list(config.CFG["interpreters"].items())

    for name, interpreter in interpreters:
        if interpreter == "native":
            valid[interpreter] = sys.executable
        elif os.path.isfile(interpreter):
            valid[interpreter] = interpreter
        elif (pth := which(interpreter)):
            valid[interpreter] = pth
        else:
            LOGGER.error(f"Could not find python interpreter `{interpreter}`. Configuration is not valid or interpreter is not installed on this system")

    return valid


def execute_interpreter(*, command: List[str], interpreter: str, stdin=None, native_callback: Optional[Callable]=None):
    """
    Run script/command inside the defined interpreter and retrieve the JSON encoded output

    :param command: command/path to script to execute
    :param interpreter: command/path to the Python interpreter used for execution
    :param stdin: stdin to pass to the execute program
    :return: json decoded stdout
    """
    if (interpreter == "native" or interpreter == sys.executable) and native_callback:
        try:
            return native_callback(command)
        except Exception as exc:
            raise PythonExecutorError(f"Native interpreter failed") from exc

    full_args = [interpreter] + command
    proc = subprocess.run(
        args=full_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        input=stdin
    )
    if proc.returncode == 0:
        payload = None
        try:
            payload = proc.stdout
            return loads(payload)
        except JSONDecodeError:
            LOGGER.exception(f"Error decoding interpreter JSON: {repr(payload)}")
            new_exception = PythonExecutorError("Error decoding python interpreter JSON")
            new_exception.stdout = payload
            new_exception.stderr = proc.stderr
            raise new_exception
    else:
        exc = PythonExecutorError(f"Interpreter exited with non-zero status code: {proc.returncode}")
        exc.stderr = proc.stderr
        exc.stdout = proc.stdout
        raise exc


def get_native_source_code(command):
    with open(command[-1], "r") as fd:
        src_dump = python_src_inspector.collect(source_code=fd.read(), minimal=True)

    src_dump.update(NATIVE_ENVIRONMENT_CACHE)
    return src_dump


def init_native_environment():
    global NATIVE_ENVIRONMENT_CACHE
    try:
        NATIVE_ENVIRONMENT_CACHE = execute_interpreter(command=[python_src_inspector.__file__, '--environment-only'], interpreter=sys.executable)
    except PythonExecutorError as exc:
        LOGGER.exception("An error occurred when pre-caching data for the native python executor")
        LOGGER.info(f"STDERR output is: {exc.stderr}")


init_native_environment()

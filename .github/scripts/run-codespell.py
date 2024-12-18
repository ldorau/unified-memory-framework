"""
 Copyright (C) 2024 Intel Corporation

 Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""

import subprocess  # nosec B404
import sys


def codespell_scan():
    try:
        codespell_result = subprocess.run(  # nosec
            [
                "codespell",
                "-H",
                "--quiet-level=3",
                "--skip=./.git,./.venv,./.github/workflows/.spellcheck-conf.toml,./.github/scripts/run-codespell.py",
            ],
            text=True,
        )
        if codespell_result.returncode != 0:
            print(codespell_result)
            sys.exit(1)
        else:
            print("No spelling errors found")
    except subprocess.CalledProcessError as ex:
        print(ex)
        sys.exit(1)


codespell_scan()

#!/usr/bin/env python

__author__ = "DFIRSec (@pulsecode)"
__version__ = "1.0"
__description__ = "Search through directories for a give file hash (sha256)."

import hashlib
import os
import re
import sys
import time
from argparse import ArgumentParser
from pathlib import Path

import pandas as pd
from tabulate import tabulate
from tqdm import tqdm

# For Windows systems
# set TABULATE_INSTALL=lib-only

file_list = []


def get_hash(file_path):
    with open(file_path, 'rb') as _file:
        file_hash = hashlib.sha256(_file.read()).hexdigest()
    return file_hash


def file_processor(workingdir):
    dirpath = Path(workingdir)
    print(f"Scanning: {dirpath} ...")
    for root, _, files in tqdm(os.walk(dirpath),
                               ascii=True,
                               desc=f"Processing",
                               ncols=80, unit=" files"):
        for filename in files:
            try:
                filepath = os.path.join(root, filename)
                ctime = time.ctime(os.stat(filepath).st_ctime)
                mtime = time.ctime(os.stat(filepath).st_mtime)
                fsize = os.stat(filepath).st_size
                file_list.append((filename, Path(filepath).parent,
                                  ctime, mtime, fsize, get_hash(filepath)))

            except KeyboardInterrupt:
                sys.exit('= Exited =')
            except PermissionError:
                print("Permission denied:", os.path.join(root, filename))
                continue
            except OSError as error:
                print("OS Error encounterd:", error)
                continue


def main(dirpath, filehash):
    if not re.match(r"\b[A-Fa-f0-9]{64}\b", filehash):
        sys.exit("[ERROR] Please enter a valid sha256 hash.")
    else:
        try:
            file_processor(dirpath)

            columns = ["File", "Path", "Created", "Modified", "Size (B)", "Hash"]  # nopep8
            df = pd.DataFrame.from_records(file_list, columns=columns)

            if df.loc[df['Hash'] == filehash].any()[0]:
                print(f"\n{tabulate(df.loc[df['Hash'] == filehash], showindex=False, headers=columns, tablefmt='github')}")  # nopep8
            else:
                print("\nHash not found.")

        except Exception as error:
            sys.exit(error)


if __name__ == "__main__":
    banner = fr"""
        __  __           __       ________              __
       / / / /___ ______/ /_     / ____/ /_  ___  _____/ /__
      / /_/ / __ `/ ___/ __ \   / /   / __ \/ _ \/ ___/ //_/
     / __  / /_/ (__  ) / / /  / /___/ / / /  __/ /__/ ,<
    /_/ /_/\__,_/____/_/ /_/   \____/_/ /_/\___/\___/_/|_|

    v{__version__}
    """

    print(banner)

    parser = ArgumentParser()
    parser.add_argument("dirpath", help="directory path to scan")
    parser.add_argument("filehash", help="the file hash you're searching for")
    args = parser.parse_args()
    filehash = args.filehash.lower()

    main(args.dirpath, filehash)

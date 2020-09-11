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

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.3"
__description__ = "Search through directories for a give file hash (sha256)."

# For Windows systems
# set TABULATE_INSTALL=lib-only

file_list = []


def hash_regex(_str):
    hash_dict = dict(
        md5=re.compile(r"\b[A-Fa-f0-9]{32}\b"),
        sha1=re.compile(r"\b[A-Fa-f0-9]{40}\b"),
        sha256=re.compile(r"\b[A-Fa-f0-9]{64}\b"),
        sha512=re.compile(r"\b[A-Fa-f0-9]{128}\b")
    )
    match = ''.join([k for k, v in hash_dict.items() if re.match(v, _str)])
    return match


def get_hash(file_path, _str):
    file_hash = ''
    hash_str = hash_regex(_str)
    with open(file_path, 'rb') as _file:
        if hash_str == 'md5':
            file_hash = hashlib.md5(_file.read()).hexdigest()
        elif hash_str == 'sha1':
            file_hash = hashlib.sha1(_file.read()).hexdigest()
        elif hash_str == 'sha256':
            file_hash = hashlib.sha256(_file.read()).hexdigest()
        elif hash_str == 'sha512':
            file_hash = hashlib.sha512(_file.read()).hexdigest()

    return file_hash


def file_processor(workingdir, filehash):
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
                                  ctime, mtime, fsize, get_hash(filepath, filehash)))

            except KeyboardInterrupt:
                sys.exit('= Exited =')
            except PermissionError:
                print("Permission denied:", os.path.join(root, filename))
                continue
            except OSError as error:
                print("OS Error encounterd:", error)
                continue


def main(dirpath, filehash):
    if not hash_regex(filehash):
        sys.exit("\033[31m[ERROR]\033[0m Please use one of the following hash types: md5, sha1, sha256, sha512")  # nopep8
    else:
        try:
            file_processor(dirpath, filehash)

            columns = ["File", "Path", "Created", "Modified", "Size (B)", "Hash"]  # nopep8
            df = pd.DataFrame.from_records(file_list, columns=columns)

            if df.loc[df['Hash'] == filehash].any()[0]:
                print(f"\n{tabulate(df.loc[df['Hash'] == filehash], showindex=False, headers=columns, tablefmt='github')}")  # nopep8
            else:
                print(f"\n{hash_regex(filehash).upper()} hash '{filehash}' was not found.") #nopep8

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
                                        {__author__}
    """

    print(f"\033[36m{banner}\033[0m")

    parser = ArgumentParser()
    parser.add_argument("dirpath", help="directory path to scan")
    parser.add_argument("filehash", help="the file hash you're searching for")
    args = parser.parse_args()
    filehash = args.filehash.lower()

    main(args.dirpath, filehash)

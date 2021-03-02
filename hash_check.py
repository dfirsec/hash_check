import hashlib
import os
import re
import sys
import time
from argparse import ArgumentParser
from pathlib import Path

import pandas as pd
from colorama import Fore, init
from tabulate import tabulate
from tqdm import tqdm

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.0.5"
__description__ = "Search directories for a give file hash (sha256)."

# terminal colors
init()
YEL = Fore.YELLOW
RST = Fore.RESET
PROC = f"{YEL}> {RST}"

# file list holder
file_list = []


def hash_regex(_str):
    hash_dict = dict(
        md5=re.compile(r"\b[A-Fa-f0-9]{32}\b"),
        sha1=re.compile(r"\b[A-Fa-f0-9]{40}\b"),
        sha256=re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    )
    match = "".join([k for k, v in hash_dict.items() if re.match(v, _str)])
    return match


def get_hash(filename, hash_str, blocksize=65536):
    global hsh
    hash_type = hash_regex(hash_str)

    if hash_type == "md5":
        hsh = hashlib.md5()
    elif hash_type == "sha1":
        hsh = hashlib.sha1()
    elif hash_type == "sha256":
        hsh = hashlib.sha256()
    elif hash_type == "sha512":
        hsh = hashlib.sha512()

    with open(filename, "rb") as f:
        while True:
            buf = f.read(blocksize)
            if not buf:
                break
            hsh.update(buf)
    return hsh.hexdigest()


def walkdir(folder):
    for root, _, files in os.walk(folder):
        for filename in files:
            yield os.path.abspath(os.path.join(root, filename))


def file_processor(workingdir, fhash):
    dirpath = Path(workingdir)
    print(f"{PROC}Scanning: {dirpath} ...")
    filecounter = 0
    for filepath in walkdir(dirpath):
        filecounter += 1

    for filepath in tqdm(walkdir(dirpath), total=filecounter, desc=f"{PROC}Processing", ncols=90, unit=" files"):
        try:
            ctime = time.ctime(os.stat(filepath).st_ctime)
            mtime = time.ctime(os.stat(filepath).st_mtime)
            fsize = os.stat(filepath).st_size
            file_list.append((filepath, Path(filepath).parent, ctime, mtime, fsize, get_hash(filepath, fhash)))

        except KeyboardInterrupt:
            sys.exit("= Exited =")
        except PermissionError:
            continue
        except OSError as error:
            print("OS Error encountered:", error)
            continue


def main(dirpath, fhash):
    if not hash_regex(fhash):
        sys.exit("\033[31m[ERROR]\033[0m Please use one of the following hash types: MD5, SHA1, SHA256")
    else:
        try:
            file_processor(dirpath, fhash)

            columns = ["File", "Path", "Created", "Modified", "Size (B)", "Hash"]
            df = pd.DataFrame.from_records(file_list, columns=columns)

            if df.loc[df["Hash"] == fhash].any()[0]:
                print(
                    f"\n{tabulate(df.loc[df['Hash'] == fhash], showindex=False, headers=columns, tablefmt='github')}"
                )
            else:
                print(f"\n{hash_regex(fhash).upper()} hash '{fhash}' was not found.")
        except Exception as error:
            sys.exit(error)


if __name__ == "__main__":
    banner = fr"""
        __  __           __       ________              __
       / / / /___ ______/ /_     / ____/ /_  ___  _____/ /__
      / /_/ / __ `/ ___/ __ \   / /   / __ \/ _ \/ ___/ //_/
     / __  / /_/ (__  ) / / /  / /___/ / / /  __/ /__/ ,<
    /_/ /_/\__,_/____/_/ /_/   \____/_/ /_/\___/\___/_/|_|

                                        {__version__}
                                        {__author__}
    """

    print(f"\033[36m{banner}\033[0m")

    parser = ArgumentParser()
    parser.add_argument("PATH", help="directory path to scan")
    parser.add_argument("HASH", help="the file hash you're searching for")
    args = parser.parse_args()
    HASH = args.HASH.lower()

    main(args.PATH, HASH)

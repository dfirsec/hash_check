import hashlib
import json
import os
import re
import sys
import time
from argparse import ArgumentParser
from functools import partial
from pathlib import Path

import pandas as pd
from colorama import Fore, init
from tabulate import tabulate
from tqdm import tqdm

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.0.8"
__description__ = "Search directories for a give file hash."

# terminal colors
init()
CYN = Fore.CYAN
YEL = Fore.YELLOW
RST = Fore.RESET
PROC = f"{YEL}> {RST}"

# file list holder
file_list = []


def hash_regex(hash_str):
    hash_dict = dict(
        md5=re.compile(r"\b[A-Fa-f0-9]{32}\b"),
        sha1=re.compile(r"\b[A-Fa-f0-9]{40}\b"),
        sha256=re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    )
    match = "".join([k for k, v in hash_dict.items() if re.match(v, hash_str)])
    return match


def gethash(filename, hash_str, blocksize=65536):
    algorithm = hash_regex(hash_str)
    hasher = hashlib.new(algorithm)

    with open(filename, "rb") as _file:
        for chunk in iter(partial(_file.read, blocksize), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def walkdir(folder):
    for root, _, files in os.walk(folder):
        for filename in files:
            yield os.path.abspath(os.path.join(root, filename))


def processor(workingdir, fhash):
    dirpath = Path(workingdir)
    print(f"{PROC}Getting file count...", sep=" ", end=" ")
    filecounter = len(list(walkdir(dirpath)))
    print(f"{filecounter:,} files")

    for filepath in tqdm(walkdir(dirpath), total=filecounter, desc=f"{PROC}Processing", ncols=90, unit=" files"):
        try:
            ctime = time.ctime(os.stat(filepath).st_ctime)
            mtime = time.ctime(os.stat(filepath).st_mtime)
            fsize = os.stat(filepath).st_size

            # create results dict to hold all key value pairs
            results_dict = {
                "File": str(Path(filepath).name),
                "Path": str(Path(filepath).parent),
                "Created": ctime,
                "Modified": mtime,
                "Size (B)": fsize,
                "Hash": gethash(filepath, fhash),
            }

            # append results dictionary to global file list
            file_list.append(results_dict.copy())

        except KeyboardInterrupt:
            sys.exit("= Exited =")
        except PermissionError:
            continue
        except OSError as error:
            print("OS Error encountered:", error)
            continue


def main(dirpath, fhash, save=None):
    if not hash_regex(fhash):
        sys.exit("\033[31m[ERROR]\033[0m Please use one of the following hash types: MD5, SHA1, SHA256")
    else:
        print(f"{PROC}Scanning: {dirpath} ...")

        # initate file processing
        processor(dirpath, fhash)

        # tabulate output to terminal and find match
        columns = ["File", "Path", "Created", "Modified", "Size (B)", "Hash"]
        data = pd.DataFrame.from_records(file_list, columns=columns)
        match = data.loc[data["Hash"] == fhash]

        if match.any()[0]:
            print(f"\n{tabulate(match, showindex=False, headers=columns, tablefmt='github')}")
            results = match.to_dict("index")
            with open("results.json", "w") as _file:
                json.dump(results, _file, indent=4)
            print(f"\n{PROC}Results saved to {CYN}results.json{RST} file")
        else:
            print(f"\n[-] No results for {hash_regex(fhash).upper()} hash: {fhash}")

        if file_list and save:
            with open("hashed_files.json", "w") as _file:
                json.dump(file_list, _file, indent=4)


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
    parser.add_argument("-s", "--save", action="store_true", help="Save hashed results to file")
    args = parser.parse_args()

    PATH = args.PATH
    HASH = args.HASH.lower()
    SAVE = args.save

    if Path(PATH).exists():
        main(PATH, HASH, SAVE)
    else:
        print(f"Path does not exist: {PATH}")

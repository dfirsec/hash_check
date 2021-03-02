# Hash Check

Search directories for a given file hash.  Currently limited to md5, sha1, sha256, and sha512 hash types.

:bulb: Note: To optimize processing, try to limit directory depth, i.e., number of subfolders to process.

## Installation

```text
git clone https://github.com/dfirsec/hash_check.git
cd hash_check
pip install -r requirements.txt
```

## Usage

```text
        __  __           __       ________              __
       / / / /___ ______/ /_     / ____/ /_  ___  _____/ /__
      / /_/ / __ `/ ___/ __ \   / /   / __ \/ _ \/ ___/ //_/
     / __  / /_/ (__  ) / / /  / /___/ / / /  __/ /__/ ,<
    /_/ /_/\__,_/____/_/ /_/   \____/_/ /_/\___/\___/_/|_|

                                        v0.0.2
                                        DFIRSec (@pulsecode)

usage: hash_check.py [-h] dirpath filehash

Search for given file hash

positional arguments:
  dirpath     directory path to scan
  filehash    the file hash you're searching for
```

## Example Run

```text
hash_check.py  D:\Downloads B02185B97857B7355543C03628437D67F320A8621EA2177D3FC978035AF72506
Processing: 64 files [00:03, 20.76 files/s]

| File       | Path                | Created                  | Modified                 |   Size (B) | Hash                                                             |
|------------|---------------------|--------------------------|--------------------------|------------|------------------------------------------------------------------|
| Hasher.exe | D:\Downloads\Hasher | Tue May 19 10:18:16 2020 | Thu Apr  2 10:14:22 2020 |   52803640 | b02185b97857b7355543c03628437d67f320a8621ea2177d3fc978035af72506 |
```

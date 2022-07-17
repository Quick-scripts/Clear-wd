#!/bin/python

from __future__ import annotations
import os
import sys

def main():
    argv: list[str] = sys.argv

    if len(argv) == 1:
        os.system("rm -rf ./*")
        return
    
    targets: list[str] = argv[1:]

    for target in targets:
        try:
            os.system("rm -rf {}".format(target))
        except Exception as e:
            sys.stderr.write("{} was not found".format(target))
        

if __name__ == "__main__":
    main()

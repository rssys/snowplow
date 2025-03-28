# A script to dump function and basic block locations, size, etc.
# Install angr (https://docs.angr.io/introductory-errata/install) before use it.

import angr
import os
import sys
import pickle
import time


def main(argv):
    if (len(argv) < 3):
        print("Usage %s <BIN> <SAVEDIR>" % argv[0])
        return -1

    vmlinux_filepath = argv[1]
    assert os.path.exists(vmlinux_filepath) is True
    save_dirpath = argv[2]
    assert os.path.exists(save_dirpath) is True

    start_time = time.time()

    # build the CFG using the fast mode
    p = angr.Project(vmlinux_filepath, main_opts={'arch': 'x86_64'}, load_options={'auto_load_libs': False})
    cfg = p.analyses.CFGFast()

    end_time = time.time()
    minutes_taken = (end_time - start_time) / 60
    print(f"Minutes taken: {minutes_taken:.2f} minutes")

    with open(f"{save_dirpath}/cfg-pickle", "wb") as tmp_f:
        pickle.dump(cfg, tmp_f, pickle.HIGHEST_PROTOCOL)
    print(f"the CFG is serialized to {save_dirpath}/cfg-pickle")


if __name__ == '__main__':
    main(sys.argv)

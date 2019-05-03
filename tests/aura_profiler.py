import sys
import os
import pathlib
import cProfile, pstats, io
from pstats import SortKey

from aura import commands

pr = cProfile.Profile()
pr.enable()

meta = {
    'verbosity': 1,
    'format': 'json',
    'min_score': 0
}

uri = f"file://{os.fspath(pathlib.Path(sys.argv[1]).absolute())}"
try:
    commands.scan_uri(uri, metadata=meta)
except:
    pass

pr.disable()
s = io.StringIO()
sortby = SortKey.CUMULATIVE
ps = pstats.Stats(pr, stream=s).strip_dirs().sort_stats(sortby)
ps.print_stats(250)
ps.dump_stats("aura_profiler.pstats")
print(s.getvalue())
with open('aura_profiler_results.log', 'w') as fd:
    fd.write(s.getvalue())

"""room_client.py with the DLL test shim: the game runs the in-process core, the Python launcher keeps the lobby and the party channels.

Lives in dllshim/ (not in reconstruction/: the launcher's source identity hashes every .py there)."""
import runpy
import sys
from pathlib import Path

sys.dont_write_bytecode = True
here = Path(__file__).resolve().parent
root = here.parent
sys.path.insert(0, str(here))
sys.path.insert(0, str(root / 'reconstruction'))
import os  # noqa: E402
import dll_shim  # noqa: E402
import unknown_build  # noqa: E402

# A build the Python adapter does not know but a DLL profile describes (the Native engine): the Python game bridges stay unloaded.
_unknown = unknown_build.detect(root, Path(os.environ.get('COOP_EXECUTABLE', root / 'AzerothSurvivors.exe')))
if _unknown:
    unknown_build.install(root, Path(os.environ.get('COOP_EXECUTABLE', root / 'AzerothSurvivors.exe')), *_unknown)
else:
    dll_shim.install()
runpy.run_path(str(root / 'reconstruction' / 'room_client.py'), run_name='__main__')

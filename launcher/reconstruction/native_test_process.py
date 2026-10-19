"""Bound disposable verifier trees to a Windows job before they can spawn."""
import ctypes as C
from ctypes import wintypes as W
import subprocess
import sys
import time


class Limits(C.Structure):
    _fields_ = [('process_time', C.c_longlong), ('job_time', C.c_longlong),
                ('flags', W.DWORD), ('minimum_working', C.c_size_t), ('maximum_working', C.c_size_t),
                ('active_limit', W.DWORD), ('affinity', C.c_size_t), ('priority', W.DWORD),
                ('scheduling', W.DWORD), ('io', C.c_ulonglong * 6),
                ('process_memory', C.c_size_t), ('job_memory', C.c_size_t),
                ('peak_process_memory', C.c_size_t), ('peak_job_memory', C.c_size_t)]


def run_verifier(command, *, cwd, env, stdout, timeout):
    kernel = C.WinDLL('kernel32', use_last_error=True)
    signatures = {
        'CreateJobObjectW': (W.HANDLE, [C.c_void_p, W.LPCWSTR]),
        'SetInformationJobObject': (W.BOOL, [W.HANDLE, C.c_int, C.c_void_p, W.DWORD]),
        'AssignProcessToJobObject': (W.BOOL, [W.HANDLE, W.HANDLE]),
        'TerminateJobObject': (W.BOOL, [W.HANDLE, W.UINT]),
        'QueryInformationJobObject': (W.BOOL, [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p]),
        'CloseHandle': (W.BOOL, [W.HANDLE]),
    }
    for name, (result, arguments) in signatures.items():
        function = getattr(kernel, name)
        function.restype, function.argtypes = result, arguments
    def checked(value):
        if not value:
            raise C.WinError(C.get_last_error())
        return value
    job = checked(kernel.CreateJobObjectW(None, None))
    process = None
    def active_processes():
        accounting = C.create_string_buffer(48)
        checked(kernel.QueryInformationJobObject(job, 1, accounting, 48, None))
        return W.DWORD.from_buffer(accounting, 40).value
    try:
        limits = Limits()
        limits.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        checked(kernel.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)))
        # The child cannot import the verifier or create descendants before
        # the parent assigns its job. Closing stdin early exits harmlessly.
        bootstrap = ("import sys,runpy,os; gate=sys.stdin.buffer.read(1); "
                     "sys.argv=sys.argv[1:]; "
                     "sys.path.insert(0,os.path.dirname(os.path.abspath(sys.argv[0]))); "
                     "runpy.run_path(sys.argv[0],run_name='__main__') if gate==b'1' else None")
        process = subprocess.Popen([sys.executable, '-c', bootstrap, *command], cwd=cwd,
            env=dict(env, PYTHONOPTIMIZE='0'), stdin=subprocess.PIPE, stdout=stdout,
            stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
        checked(kernel.AssignProcessToJobObject(job, W.HANDLE(int(process._handle))))
        process.stdin.write(b'1')
        process.stdin.close()
        code = process.wait(timeout=timeout)
        until = time.monotonic() + 2
        while active_processes() and time.monotonic() < until:
            time.sleep(.05)
        if code == 0 and active_processes():
            print('Verifier exited with live descendants; forced cleanup is not a passing test.',
                  file=stdout, flush=True)
            code = 1
        return subprocess.CompletedProcess(command, code)
    finally:
        try:
            checked(kernel.TerminateJobObject(job, 1))
            if process is not None:
                if process.stdin and not process.stdin.closed:
                    process.stdin.close()
                process.wait(timeout=10)
            until = time.monotonic() + 10
            while True:
                if active_processes() == 0:
                    break
                if time.monotonic() >= until:
                    raise RuntimeError('Disposable test processes did not leave their job')
                time.sleep(.05)
        finally:
            kernel.CloseHandle(job)

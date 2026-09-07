import time

def time_call(function, repeats=10):
    """Return average seconds per call; increase repeats for very fast operations."""
    # MODIFY repeats. Do setup outside this function if only the operation is timed.
    start = time.perf_counter()
    for _ in range(repeats):
        function()
    return (time.perf_counter() - start) / repeats

if __name__ == '__main__':
    # Replace the lambda with: lambda: cipher.encrypt(data)
    print(time_call(lambda: sum(range(10000))))

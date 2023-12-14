from multiprocessing import Pool


def init_pool(num_processes=5):
    global POOL
    try:
        POOL.terminate()
        POOL.join()
    except:
        pass
    POOL = Pool(processes=num_processes)

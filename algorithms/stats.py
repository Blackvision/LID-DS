import pstats

# python -m cProfile -o stats_ids_sys_net_main.prof ids_sys_net_main.py
# snakeviz stats_ids_sys_net_main.prof

if __name__ == '__main__':
    p = pstats.Stats('pi.prof')
    p.sort_stats('time').print_stats(8)

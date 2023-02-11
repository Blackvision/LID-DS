from algorithms.features.impl_syscall.unknown_flags import UnknownFlags
from dataloader.syscall_2021 import Syscall2021


def test_unknown_flag():
    syscall_1 = Syscall2021("",
        "1631209047761484608 0 10 apache2 10 open < flags=test fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max mode=0 dev=200024")

    syscall_2 = Syscall2021("",
        "1631209047762064269 0 11 apache2 11 open < flags=test2 fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group mode=0 dev=200021 ")

    syscall_3 = Syscall2021("",
        "1631209047762064269 0 12 apache2 12 poll < flags=test3 fd=9(<f>/etc/group) name=/etc/group mode=0 dev=200021 ")

    syscall_4 = Syscall2021("",
        "1631209047762064269 0 13 apache2 13 open < flags=test in_fd=9(<f>/etc/test) name=/etc/group mode=0 dev=200021 ")

    syscall_5 = Syscall2021("",
        "1631209047762064269 0 12 apache2 12 open < flags=test4 out_fd=9(<f>/etc/password) name=/etc/group mode=0 dev=200021 ")

    f = UnknownFlags()

    f.train_on(syscall_1)
    assert f._flag_dict == {'open': ['test']}

    f.train_on(syscall_2)
    assert f._flag_dict == {'open': ['test', 'test2']}

    f.train_on(syscall_3)
    assert f._flag_dict == {'open': ['test', 'test2'],
                            'poll': ['test3']}
    
    assert f._calculate(syscall_4) == 0
    assert f._calculate(syscall_5) == 1

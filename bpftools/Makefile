# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）

.PHONY:all ipc process syscall files tcp container

all: ipc process syscall files tcp container

ipc:
	@make -C ipc

process:
	@make -C process

syscall:
	@make -C syscall

files:
	@make -C files

tcp:
	@make -C tcp

container:
	@make -C container

clean:
	@make -C files clean
	@make -C process clean
	@make -C syscall clean
	@make -C ipc clean
	@make -C tcp clean
	@make -C container clean
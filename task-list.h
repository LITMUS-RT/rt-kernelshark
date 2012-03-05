#ifndef __TASK_LIST_H
#define __TASK_LIST_H

#include <gtk/gtk.h>
#include "trace-cmd.h"
#include "trace-hash.h"

#define TASK_HASH_SIZE 1024

struct task_list {
	struct task_list	*next;
	gint			pid;
};

struct task_list* find_task_list(struct task_list **tasks, int pid);
struct task_list* add_task_hash(struct task_list **tasks, int pid);
void free_task_hash(struct task_list **tasks);
gint* task_list_pids(struct task_list **tasks);

#endif

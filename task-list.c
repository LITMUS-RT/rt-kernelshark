#include "task-list.h"

static guint get_task_hash_key(gint pid)
{
	return trace_hash(pid) % TASK_HASH_SIZE;
}

struct task_list *find_task_hash(struct task_list **tasks,
				 gint key, gint pid)
{
	struct task_list *list;

	for (list = tasks[key]; list; list = list->next) {
		if (list->pid == pid)
			return list;
	}

	return NULL;
}

/**
 * find_task_list - return task_list node for pid, or NULL if not present
 */
struct task_list *find_task_list(struct task_list **tasks, gint pid)
{
	guint key = get_task_hash_key(pid);
	return find_task_hash(tasks, key, pid);
}

/**
 * add_task_hash - add pid to a task_list
 * @tasks: The head of the task_list
 * @pid: The pid to add
 *
 * Return the list entry of the added task
 */
struct task_list *add_task_hash(struct task_list **tasks, int pid)
{
	struct task_list *list;
	guint key = get_task_hash_key(pid);

	list = find_task_hash(tasks, key, pid);
	if (list)
		return list;

	list = malloc_or_die(sizeof(*list));
	list->pid = pid;
	list->next = tasks[key];
	list->data = NULL;
	tasks[key] = list;

	return list;
}

/**
 * free_task_hash - free all nodes in a task_list
 */
void free_task_hash(struct task_list **tasks)
{
	struct task_list *list;
	int i;

	for (i = 0; i < TASK_HASH_SIZE; i++) {
		while (tasks[i]) {
			list = tasks[i];
			tasks[i] = list->next;
			free(list->data);
			free(list);
		}
	}
}

/**
 * task_list_pids - return an allocated list of all found tasks
 * @ginfo: The graph info structure
 *
 * Returns an allocated list of pids found in the graph, ending
 * with a -1. This array must be freed with free().
 */
gint *task_list_pids(struct task_list **tasks)
{
	struct task_list *list;
	gint *pids;
	gint count = 0;
	gint i;

	for (i = 0; i < TASK_HASH_SIZE; i++) {
		list = tasks[i];
		while (list) {
			if (count)
				pids = realloc(pids, sizeof(*pids) * (count + 2));
			else
				pids = malloc(sizeof(*pids) * 2);
			pids[count++] = list->pid;
			pids[count] = -1;
			list = list->next;
		}
	}

	return pids;
}

/**
 * Plot real-time events for a single virtual CPU of a container.
 */
#include "trace-graph.h"

struct vcpu_list;

struct vcpu_info {
	struct rt_plot_common	common;

	int			sid;

	/* What the vcpu is running */
	int			task_tid;
	int			task_cpu;
	unsigned long long	task_run_time;
	gboolean		task_running;
	gboolean		task_exec;

	/* How the vcpu is running */
	int			server_job;
	int			server_cpu;
	unsigned long long	server_run_time;
	gboolean		server_running;

	/* Server blocking */
	unsigned long long	block_time;
	int			block_cpu;
	gboolean		blocked;

	gboolean		fresh;
	gboolean		spare;

	/* False if we should only show what the vcpu is running, not
	 * WHEN the CPU is running
	 */
	gboolean		show_server;

	char			*task_label;
	char			*server_label;

	struct cont_list	*cont;
};

void insert_vcpu(struct graph_info *ginfo, struct cont_list *cont,
		 struct vcpu_list *vcpu_info);

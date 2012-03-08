#ifndef __RT_PLOT_TASK_H
#define __RT_PLOT_TASK_H

#include "trace-plot-task.h"

struct rt_task_info {
	int			pid;
	unsigned long long	wcet;
	unsigned long long	period;

	/* For drawing squares */
	unsigned long long	run_time;
	int			run_cpu;
	unsigned long long	block_time;
	int			block_cpu;

	/* For managing state */
	int			last_job;

	/* Used to get around bugs(ish) */
	unsigned long long	first_rels[3];

	gboolean		params_found;
	gboolean		fresh;
	char			*label;
};

void rt_plot_task(struct graph_info *ginfo, int pid, int pos);
void rt_plot_task_plotted(struct graph_info *ginfo, gint **plotted);
void rt_plot_task_update_callback(gboolean accept, gint *selected,
				  gint *non_select, gpointer data);
#endif

#ifndef __RT_PLOT_TASK_H
#define __RT_PLOT_TASK_H

#include "trace-plot-task.h"

struct rt_task_info {
	struct task_plot_info	base;
	unsigned long long	wcet;
	unsigned long long	period;
	unsigned long long	block_time;
	int			last_job;
	gboolean		params_found;
	char			*label;
};

void rt_plot_task(struct graph_info *ginfo, int pid, int pos);
void rt_plot_task_plotted(struct graph_info *ginfo, gint **plotted);
void rt_plot_task_update_callback(gboolean accept, gint *selected,
				  gint *non_select, gpointer data);
#endif

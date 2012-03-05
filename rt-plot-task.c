#include "trace-graph.h"

static const struct plot_callbacks rt_task_cb = {
	.match_time		= task_plot_match_time,
	.plot_event		= task_plot_event,
	.start			= task_plot_start,
	.display_last_event	= task_plot_display_last_event,
	.find_record		= task_plot_find_record,
	.display_info		= task_plot_display_info,
	.destroy		= task_plot_destroy
};

void rt_plot_task_update_callback(gboolean accept,
				  gint *selected,
				  gint *non_select,
				  gpointer data)
{
	graph_tasks_update_callback(TASK_PLOT_RT, rt_plot_task,
				    accept, selected, non_select, data);
}

void rt_plot_task_plotted(struct graph_info *ginfo, gint **plotted)
{
	graph_tasks_plotted(ginfo, TASK_PLOT_RT, plotted);
}

void rt_plot_task(struct graph_info *ginfo, int pid, int pos)
{
	struct rt_graph_info *rtinfo = &ginfo->rtinfo;
	struct rt_task_info *rt_task;
	struct graph_plot *plot;
	const char *comm;
	char *label;
	int len;

	if (!find_task_list(rtinfo->tasks, pid))
		die("Cannot create RT plot of non-RT task %d!\n", pid);

	rt_task = malloc_or_die(sizeof(*rt_task));

	init_task_plot_info(ginfo, &rt_task->base, TASK_PLOT_RT, pid);

	comm = pevent_data_comm_from_pid(ginfo->pevent, pid);
	len = strlen(comm) + 100;
	label = malloc_or_die(len);
	snprintf(label, len, "*%s-%d", comm, pid);

	plot = trace_graph_plot_insert(ginfo, pos, label, PLOT_TYPE_TASK,
				       &rt_task_cb, rt_task);
	free(label);

	trace_graph_plot_add_all_recs(ginfo, plot);
}


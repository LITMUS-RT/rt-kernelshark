#ifndef __RT_PLOT_CPU_H
#define __RT_PLOT_CPU_H

struct rt_cpu_info {
	int			cpu;
	unsigned long long	run_time;
	int			run_pid;
	gboolean 		fresh;
	char			*label;
};

void rt_plot_cpu(struct graph_info *ginfo, int cpu);
void rt_plot_cpus_plotted(struct graph_info *ginfo,
			  gboolean *all_cpus, guint64 **cpu_mask);
void rt_plot_cpus_update_callback(gboolean accept,
				  gboolean all_cpus,
				  guint64 *selected_cpu_mask,
				  gpointer data);

#endif

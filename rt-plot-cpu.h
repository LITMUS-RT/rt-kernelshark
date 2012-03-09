#ifndef __RT_PLOT_CPU_H
#define __RT_PLOT_CPU_H

struct rt_cpu_info {
	int			cpu;
	int			run_pid;
	unsigned long long	rt_run_time;
	unsigned long long	reg_run_time;
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
void rt_plot_init_cpus(struct graph_info *ginfo, int cpus);

#endif

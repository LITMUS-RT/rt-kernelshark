#ifndef __TRACE_PLOT_TASK_H
#define __TRACE_PLOT_TASK_H

#include <gtk/gtk.h>

#include "trace-cmd.h"

struct graph_info;
struct graph_plot;
struct plot_info;
enum graph_plot_type;

/**
 * struct task_plot_info - information for plotting a single task
 * @pid: pid to plot
 * @cpu_data: state of each cpu
 * @last_records: cache of recently accessed records
 * @last_time: time of last record seen by this task graph
 * @wake_time: time task resumed execution
 * @display_wake_time: as above, but reset under some circumstances
 * @wake_color:
 * @last_cpu: cpu task is currently running on
 */
struct task_plot_info {
	int			pid;
	struct cpu_data		*cpu_data;
	struct record		**last_records;
	unsigned long long	last_time;
	unsigned long long	wake_time;
	unsigned long long	display_wake_time;
	int			wake_color;
	int			last_cpu;
};

/* Querying records */
gboolean is_running(struct graph_info *ginfo, struct record *record);

/* State maintenance */
void update_last_task_record(struct graph_info *ginfo, struct task_plot_info *task_info,
			     struct record *record);

/* Searching for records */
#define MAX_SEARCH 20
struct record *find_previous_record(struct graph_info *ginfo,
					   struct record *start_record,
					   int pid, int cpu);
struct record *get_display_record(struct graph_info *ginfo, int pid,
				  unsigned long long time);

/* Saving / restoring state */
struct offset_cache {
	guint64 *offsets;
};
struct offset_cache *save_offsets(struct graph_info *ginfo);
void restore_offsets(struct graph_info *ginfo, struct offset_cache *offsets);

/* Callbacks */
int task_plot_match_time(struct graph_info *ginfo, struct graph_plot *plot,
			 unsigned long long time);
int task_plot_display_last_event(struct graph_info *ginfo,
				 struct graph_plot *plot,
				 struct trace_seq *s,
				 unsigned long long time);
void task_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
		     unsigned long long time);
int task_plot_event(struct graph_info *ginfo, struct graph_plot *plot,
		    struct record *record, struct plot_info *info);
struct record *task_plot_find_record(struct graph_info *ginfo,
				     struct graph_plot *plot,
				     unsigned long long time);
int task_plot_display_info(struct graph_info *ginfo,
			   struct graph_plot *plot,
			   struct trace_seq *s,
			   unsigned long long time);
void task_plot_destroy(struct graph_info *ginfo, struct graph_plot *plot);

/* Plot management */
void graph_plot_task(struct graph_info *ginfo, int pid, int pos);
void graph_plot_task_plotted(struct graph_info *ginfo,
			     gint **plotted);

void graph_plot_task_update_callback(gboolean accept,
				     gint *selected,
				     gint *non_select,
				     gpointer data);

void graph_plot_init_tasks(struct graph_info *ginfo);

/* Shared functionality for inheriting structs */
typedef void (plot_task_cb)(struct graph_info *ginfo, int pid, int pos);
void graph_tasks_update_callback(enum graph_plot_type type,
				 plot_task_cb plot_cb,
				 gboolean accept,
				 gint *selected,
				 gint *non_select,
				 gpointer data);
#endif

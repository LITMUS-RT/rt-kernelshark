#ifndef __RT_PLOT_H
#define __RT_PLOT_H

#include <gtk/gtk.h>
#include "trace-cmd.h"

struct graph_plot;
struct graph_info;
struct rt_plot_common;

typedef int (*record_matches_cb)(struct rt_plot_common *rt,
				 struct graph_info *ginfo,
				 struct record *record);
typedef int (*is_drawn_cb)(struct graph_info *ginfo, int eid);
typedef struct record* (*write_header_cb)(struct rt_plot_common *rt,
					  struct graph_info *ginfo,
					  struct trace_seq *s,
					  unsigned long long time);
struct rt_plot_common {
	record_matches_cb 	record_matches;
	is_drawn_cb		is_drawn;
	write_header_cb		write_header;
};

int
rt_plot_display_last_event(struct graph_info *ginfo, struct graph_plot *plot,
			   struct trace_seq *s, unsigned long long time);
int
rt_plot_display_info(struct graph_info *ginfo, struct graph_plot *plot,
		     struct trace_seq *s, unsigned long long time);
struct record*
rt_plot_find_record(struct graph_info *ginfo, struct graph_plot *plot,
		    unsigned long long time);
int
rt_plot_match_time(struct graph_info *ginfo, struct graph_plot *plot,
		   unsigned long long time);
struct record*
__find_rt_record(struct graph_info *ginfo, struct rt_plot_common *rt,
		 guint64 time, int display, unsigned long long range);

static inline struct record*
find_rt_record(struct graph_info *ginfo, struct rt_plot_common *rt, guint64 time)
{
	return __find_rt_record(ginfo, rt, time, 0, 0);
}

static inline struct record*
find_rt_display_record(struct graph_info *ginfo,
		       struct rt_plot_common *rt, guint64 time)
{
	return __find_rt_record(ginfo, rt, time, 1, 0);
}

unsigned long long next_rts(struct graph_info *ginfo, int cpu,
			    unsigned long long ft_target);
void set_cpu_to_rts(struct graph_info *ginfo,
		    unsigned long long rt_target, int cpu);
void set_cpus_to_rts(struct graph_info *ginfo,
		     unsigned long long rt_target);
int is_task_running(struct graph_info *ginfo,
		    unsigned long long time,
		    int pid);
void get_previous_release(struct graph_info *ginfo, int tid,
			  unsigned long long time, int *job,
			  unsigned long long *release,
			  unsigned long long *deadline);

#endif

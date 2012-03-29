#ifndef __RT_PLOT_CONTAINER_H
#define __RT_PLOT_CONTAINER_H

#include "rt-plot-vcpu.h"
#include "rt-plot-vtask.h"

typedef void (*cont_dialog_cb_func)(gboolean, gint*, gint*, gpointer);

void trace_container_dialog(struct graph_info *ginfo,
			    gpointer data);
void rt_plot_container(struct graph_info *ginfo, int cid);
int rt_plot_get_containers(struct graph_info *ginfo, gint **plotted,
			    gboolean plotted_only);
void rt_plot_add_all_containers(struct graph_info *ginfo);

int get_server_info(struct graph_info *ginfo,
		    struct rt_plot_common *rt,
		    int match_sid, unsigned long long time,
		    unsigned long long *release, unsigned long long *deadline,
		    int *job, int *tid, struct record **record);

#endif

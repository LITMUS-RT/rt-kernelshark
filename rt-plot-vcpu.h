#include "trace-graph.h"

struct vcpu_list;

struct vcpu_info {
	struct rt_plot_common	common;

	int			sid;

	int			run_tid;
	int			run_cpu;
	unsigned long long	run_time;

	int			last_job;

	int			block_cpu;
	unsigned long long	block_time;

	gboolean		fresh;
	gboolean		running;

	char			*label;

	struct cont_list	*cont;
};

void insert_vcpu(struct graph_info *ginfo, struct cont_list *cont,
		 struct vcpu_list *vcpu_info);


/* drawing methods */
int vcpu_try_release(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		     struct record *record, struct plot_info *info);
int vcpu_try_completion(struct graph_info *ginfo,
			struct vcpu_info *vcpu_info,
			struct record *record, struct plot_info *info);
int vcpu_try_block(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		   struct record *record, struct plot_info *info);
int vcpu_try_resume(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		    struct record *record, struct plot_info *info);

/* trace-plot methods */
void rt_vcpu_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
			unsigned long long time);
void rt_vcpu_plot_destroy(struct graph_info *ginfo, struct graph_plot *plot);

/* rt-plot-common methods */
int rt_vcpu_plot_record_matches(struct rt_plot_common *rt,
				struct graph_info *ginfo,
				struct record *record);
int rt_vcpu_plot_is_drawn(struct graph_info *ginfo, int eid);
struct record*
rt_vcpu_plot_write_header(struct rt_plot_common *rt,
			  struct graph_info *ginfo,
			  struct trace_seq *s,
			  unsigned long long time);

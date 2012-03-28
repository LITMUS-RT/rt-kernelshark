#include "trace-graph.h"

struct vcpu_list;

struct vcpu_info {
	struct rt_plot_common	common;

	int			sid;

	int			run_tid;
	int			run_cpu;
	unsigned long long	run_time;

	int			block_cpu;
	unsigned long long	block_time;

	gboolean		fresh;
	gboolean		running;

	char			*label;

	struct cont_list	*cont;
};

void insert_vcpu(struct graph_info *ginfo, struct cont_list *cont,
		 struct vcpu_list *vcpu_info);

#include <stdio.h>
#include <string.h>
#include "trace-graph.h"

#define DEBUG_LEVEL 0
#if DEBUG_LEVEL > 0
#define dprintf(l, x...)			\
	do {					\
		if (l <= DEBUG_LEVEL)		\
			printf(x);		\
	} while (0)
#else
#define dprintf(l, x...)	do { if (0) printf(x); } while (0)
#endif

static void update_job(struct vcpu_info *info, int job)
{
	info->fresh = FALSE;
	if (job < info->last_job) {
		dprintf(1, "Inconsistent job state for server %d:%d -> %d\n",
		       info->sid, info->last_job, job);
	}

	if (job > info->last_job) {
		info->last_job = job;
		snprintf(info->label, LLABEL, "%d:%d",
			 info->sid, info->last_job);
	}
}

static int
try_server_switch_away(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		struct record *record, struct plot_info *info)
{
	int job, sid, tid, tjob, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_switch_away(ginfo, record,
						  &sid, &job,
						  &tid, &tjob, &ts);
	if (match && tid == vcpu_info->sid) {
		update_job(vcpu_info, tjob);

		if (vcpu_info->run_time && vcpu_info->run_time < ts) {
			info->box = TRUE;
			info->bcolor = hash_cpu(sid - 1);
			info->bfill = TRUE;
			info->bstart = vcpu_info->run_time;
			info->bend = ts;
			info->blabel = vcpu_info->label;
		}

		dprintf(3, "VCPU switch away from %d on %d:%d at %llu\n",
			tid, sid, job, ts);
		vcpu_info->run_time = 0ULL;
		vcpu_info->run_cpu = NO_CPU;
		vcpu_info->run_tid = 0;

		ret = 1;
	}

	return ret;
}

static int try_server_switch_to(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
				struct record *record, struct plot_info *info)
{
	int job, sid, tid, tjob, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_switch_to(ginfo, record,
						&sid, &job, &tid, &tjob, &ts);
	if (match && tid == vcpu_info->sid) {
		update_job(vcpu_info, tjob);
		vcpu_info->run_time = ts;
		vcpu_info->run_cpu = record->cpu;
		vcpu_info->run_tid = tid;
		dprintf(3, "Switch to %d for %d:%d at %llu\n",
			tid, sid, job, ts);
		ret = 1;
	}
	return ret;
}

/* static int try_switch_to(struct graph_info *ginfo, struct vcpu_info *vcpu_info, */
/* 			 struct record *record, struct plot_info *info) */
/* { */
/* 	int job, pid, match, ret = 0; */
/* 	unsigned long long ts; */

/* 	match = rt_graph_check_switch_to(ginfo, record, &pid, &job, &ts); */
/* 	if (match && pid && pid == vcpu_info->run_tid && vcpu_info->run_time) { */
/* 		info->line = TRUE; */
/* 		info->lcolor = hash_pid(pid); */
/* 		ret = 1; */
/* 	} */
/* 	return ret; */
/* } */

/* static int try_switch_away(struct graph_info *ginfo, struct vcpu_info *vcpu_info, */
/* 			   struct record *record, struct plot_info *info) */
/* { */
/* 	int job, pid, match, ret = 0; */
/* 	unsigned long long ts; */

/* 	match = rt_graph_check_switch_away(ginfo, record, &pid, &job, &ts); */
/* 	if (match && pid && pid == vcpu_info->run_tid) { */
/* 		info->line = TRUE; */
/* 		info->lcolor = hash_pid(pid); */
/* 		ret = 1; */
/* 	} */
/* 	return ret; */
/* } */

static void do_plot_end(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
			struct plot_info *info)
{
	int tid, job, is_running, tjob;
	unsigned long long deadline, release;
	struct record *record;

	if (ginfo->view_end_time == ginfo->end_time)
		return;

	if (vcpu_info->run_time && vcpu_info->run_cpu != NO_CPU) {
		info->box = TRUE;
		info->bcolor = hash_pid(vcpu_info->sid);
		info->bfill = TRUE;
		info->bstart = vcpu_info->run_time;
		info->bend = ginfo->view_end_time;
		info->blabel = vcpu_info->label;
	} else if (vcpu_info->fresh) {
		is_running = get_server_info(ginfo,
					     (struct rt_plot_common*)vcpu_info,
					     vcpu_info->sid,
					     ginfo->view_end_time,
					     &release, &deadline,
					     &job, &tid, &tjob, &record);
		if (is_running) {
			update_job(vcpu_info, job);
			info->box = TRUE;
			info->bcolor = hash_pid(vcpu_info->sid);
			info->bfill = TRUE;
			info->bstart = vcpu_info->run_time;
			info->bend = ginfo->view_end_time;
			info->blabel = vcpu_info->label;
		}
	}
}

static int rt_vtask_plot_event(struct graph_info *ginfo, struct graph_plot *plot,
			     struct record *record, struct plot_info *info)
{
	int match;
	struct vcpu_info *vcpu_info = plot->private;

	if (!record) {
		do_plot_end(ginfo, vcpu_info, info);
		return 0;
	}

	match = try_server_switch_away(ginfo, vcpu_info, record, info) ||
		try_server_switch_to(ginfo, vcpu_info, record, info) ||
		/* vcpu_try_block(ginfo, vcpu_info, record, info) || */
		/* vcpu_try_resume(ginfo, vcpu_info, record, info) || */
		vcpu_try_release(ginfo, vcpu_info, record, info) ||
		vcpu_try_completion(ginfo, vcpu_info, record, info);
		/* try_switch_to(ginfo, vcpu_info, record, info) || */
		/* try_switch_away(ginfo, vcpu_info, record, info); */
	return match;
}

const struct plot_callbacks rt_vtask_cb = {
	.start			= rt_vcpu_plot_start,
	.destroy		= rt_vcpu_plot_destroy,
	.plot_event		= rt_vtask_plot_event,
	.display_last_event	= rt_plot_display_last_event,
	.display_info		= rt_plot_display_info,
	.match_time		= rt_plot_match_time,
	.find_record		= rt_plot_find_record,
};

void insert_vtask(struct graph_info *ginfo, struct cont_list *cont,
		  struct vcpu_list *vcpu_info)
{
	struct graph_plot *plot;
	struct vcpu_info *vtask;
	char *label;

	vtask = malloc_or_die(sizeof(*vtask));
	vtask->sid = vcpu_info->sid;
	vtask->label = malloc_or_die(LLABEL);
	vtask->cont = cont;

	vtask->common.record_matches = rt_vcpu_plot_record_matches;
	vtask->common.is_drawn = rt_vcpu_plot_is_drawn;
	vtask->common.write_header = rt_vcpu_plot_write_header;

	label = malloc_or_die(1);
	snprintf(label, 2, " ");

	plot = trace_graph_plot_append(ginfo, label, PLOT_TYPE_SERVER_TASK,
				       TIME_TYPE_RT, &rt_vtask_cb, vtask);
	trace_graph_plot_add_all_recs(ginfo, plot);
}

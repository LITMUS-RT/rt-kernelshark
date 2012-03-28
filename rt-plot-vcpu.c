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

static void update_tid(struct vcpu_info *info, int tid)
{
	info->fresh = FALSE;
	if (tid != info->run_tid) {
		info->run_tid = tid;
		snprintf(info->label, LLABEL, "%d", tid);
	}
}


static int try_release(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		       struct record *record, struct plot_info *info)
{
	int sid, job, match, ret = 0;
	unsigned long long release, deadline;

	match = rt_graph_check_server_release(ginfo, record, &sid, &job,
					      &release, &deadline);
	if (match && sid == vcpu_info->sid) {
		info->release = TRUE;
		info->rtime = release;

		info->deadline = TRUE;
		info->dtime = deadline;

		dprintf(3, "VCPU release for %d:%d on %d, rel: %llu, dead: %llu\n",
			sid, job, record->cpu, release, deadline);

		ret = 1;
	}
	return ret;
}

static int try_completion(struct graph_info *ginfo,
			  struct vcpu_info *vcpu_info,
			  struct record *record, struct plot_info *info)
{
	int sid, job, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_completion(ginfo, record, &sid, &job, &ts);
	if (match && sid == vcpu_info->sid) {

		info->completion = TRUE;
		info->ctime = ts;

		dprintf(3, "VCPU completion for %d:%d on %d at %llu\n",
			sid, job, record->cpu, ts);
		ret = 1;
	}
	return ret;
}

static int try_block(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		     struct record *record, struct plot_info *info)
{
	int sid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_block(ginfo, record, &sid, &ts);
	if (match && sid == vcpu_info->sid) {
		vcpu_info->fresh = FALSE;
		vcpu_info->block_time = ts;
		vcpu_info->block_cpu = NO_CPU;
		dprintf(3, "VCPU resume for %d on %d at %llu\n",
			sid, record->cpu, ts);
		ret = 1;
	}
	return ret;
}

static int try_resume(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		      struct record *record, struct plot_info *info)
{
	int sid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_resume(ginfo, record, &sid, &ts);

	if (match && sid == vcpu_info->sid) {
		info->box = TRUE;
		info->bcolor = 0x0;
		info->bfill = TRUE;
		info->bthin = TRUE;
		info->bstart = vcpu_info->block_time;
		info->bend = ts;
		vcpu_info->fresh = FALSE;

		vcpu_info->block_time = 0ULL;
		vcpu_info->block_cpu = NO_CPU;
		dprintf(3, "VCPU resume for %d on %d at %llu\n",
			sid, record->cpu, ts);

		ret = 1;
	}
	return ret;
}

static int
try_server_switch_away(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		struct record *record, struct plot_info *info)
{
	int job, sid, tid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_switch_away(ginfo, record,
						  &sid, &job,
						  &tid, &ts);
	if (match && sid == vcpu_info->sid) {
		update_tid(vcpu_info, tid);

		if (vcpu_info->run_time && vcpu_info->run_time < ts &&
		    job != 1) {
			info->box = TRUE;
			info->bcolor = hash_pid(tid);
			info->bfill = vcpu_info->running;
			info->bstart = vcpu_info->run_time;
			info->bend = ts;
			info->blabel = vcpu_info->label;
		}

		dprintf(3, "VCPU switch away from %d on %d:%d at %llu\n",
			tid, sid, job, ts);
		vcpu_info->run_time = 0ULL;
		vcpu_info->run_cpu = NO_CPU;
		vcpu_info->run_tid = 0;
		vcpu_info->running = FALSE;

		ret = 1;
	}

	return ret;
}

static int try_server_switch_to(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
				struct record *record, struct plot_info *info)
{
	int job, sid, tid,  match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_switch_to(ginfo, record,
						&sid, &job, &tid, &ts);
	if (match && sid == vcpu_info->sid) {
		update_tid(vcpu_info, tid);
		vcpu_info->run_time = ts;
		vcpu_info->run_cpu = record->cpu;
		vcpu_info->run_tid = tid;
		dprintf(3, "Switch to %d for %d:%d at %llu\n",
			tid, sid, job, ts);
		ret = 1;
	}
	return ret;
}

static int try_switch_to(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
			 struct record *record, struct plot_info *info)
{
	int job, pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_switch_to(ginfo, record, &pid, &job, &ts);
	if (match && pid && pid == vcpu_info->run_tid && vcpu_info->run_time) {
		vcpu_info->running = TRUE;

		/* Draw empty box for time spent not running a task */
		info->box = TRUE;
		info->bcolor = hash_pid(pid);
		info->bfill = FALSE;
		info->bstart = vcpu_info->run_time;
		info->bend = ts;
		info->blabel = vcpu_info->label;

		vcpu_info->run_time = ts;
		ret = 1;
	}
	return ret;
}

static int try_switch_away(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
			   struct record *record, struct plot_info *info)
{
	int job, pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_switch_away(ginfo, record, &pid, &job, &ts);
	if (match && pid && pid == vcpu_info->run_tid && vcpu_info->running) {
		vcpu_info->running = FALSE;

		info->box = TRUE;
		info->bcolor = hash_pid(pid);
		info->bfill = TRUE;
		info->bstart = vcpu_info->run_time;
		info->bend = ts;
		info->blabel = vcpu_info->label;

		vcpu_info->run_time = ts;
		ret = 1;
	}
	return ret;
}


static void do_plot_end(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
			struct plot_info *info)
{
	/* TODO: me */
}


static int rt_vcpu_plot_event(struct graph_info *ginfo, struct graph_plot *plot,
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
		try_block(ginfo, vcpu_info, record, info) ||
		try_resume(ginfo, vcpu_info, record, info) ||
		try_release(ginfo, vcpu_info, record, info) ||
		try_completion(ginfo, vcpu_info, record, info) ||
		try_switch_to(ginfo, vcpu_info, record, info) ||
		try_switch_away(ginfo, vcpu_info, record, info);
	return match;
}

static void rt_vcpu_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
			       unsigned long long time)
{
	struct vcpu_info *vcpu_info = plot->private;

	dprintf(4,"%s\n", __FUNCTION__);

	vcpu_info->run_time = time;
	vcpu_info->block_time = time;
	vcpu_info->run_cpu = NO_CPU;
	vcpu_info->run_tid = 0;
	vcpu_info->block_cpu = NO_CPU;
	vcpu_info->fresh = FALSE;

	vcpu_info->fresh = TRUE;
	vcpu_info->running = FALSE;

	vcpu_info->run_tid = -1;
	update_tid(vcpu_info, 0);
}

static void rt_vcpu_plot_destroy(struct graph_info *ginfo, struct graph_plot *plot)
{
	struct vcpu_info *vcpu_info = plot->private;
	trace_graph_plot_remove_all_recs(ginfo, plot);
	free(vcpu_info->label);
	free(vcpu_info);
}

/*
 * Return 1 if @record is relevant to @match_sid.
 */
static int rt_vcpu_plot_record_matches(struct rt_plot_common *rt,
				       struct graph_info *ginfo,
				       struct record *record)
{
	struct vcpu_info *vcpu_info = (struct vcpu_info*)rt;
	int dint, sid, match;
	unsigned long long dull;

#define ARG ginfo, record, &sid
	match = rt_graph_check_server_switch_to(ARG, &dint, &dint, &dull)   ||
		rt_graph_check_server_switch_away(ARG, &dint, &dint, &dull) ||
		rt_graph_check_server_completion(ARG, &dint, &dull)  ||
		rt_graph_check_server_release(ARG, &dint, &dull, &dull)     ||
		rt_graph_check_server_block(ARG, &dull)			    ||
		rt_graph_check_server_resume(ARG, &dull);
#undef ARG
	return (sid == vcpu_info->sid);
}

/*
 * Return true if the given record type is drawn on screen. This does not
 * include event line markes.
 */
static int
rt_vcpu_plot_is_drawn(struct graph_info *ginfo, int eid)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	return (eid == rtg_info->server_switch_to_id   ||
		eid == rtg_info->server_switch_away_id ||
		eid == rtg_info->server_release_id     ||
		eid == rtg_info->server_completion_id  ||
		eid == rtg_info->server_block_id       ||
		eid == rtg_info->server_resume_id);
}

static struct record*
rt_vcpu_plot_write_header(struct rt_plot_common *rt,
			  struct graph_info *ginfo,
			  struct trace_seq *s,
			  unsigned long long time)
{
	int is_running, job, tid;
	unsigned long long release, deadline;
	struct vcpu_info *vcpu_info = (struct vcpu_info*)rt;
	struct record *record;

	is_running = get_server_info(ginfo, rt, vcpu_info->sid, time,
				   &release, &deadline,
				   &job, &tid, &record);

	trace_seq_printf(s, "%s-%d:%d", vcpu_info->cont->name,
			 vcpu_info->sid, job);
	if (is_running) {
		trace_seq_printf(s, " - %d", tid);
	}
	trace_seq_putc(s, '\n');
	return record;
}


const struct plot_callbacks rt_vcpu_cb = {
	.start			= rt_vcpu_plot_start,
	.destroy		= rt_vcpu_plot_destroy,
	.plot_event		= rt_vcpu_plot_event,
	.display_last_event	= rt_plot_display_last_event,
	.display_info		= rt_plot_display_info,
	.match_time		= rt_plot_match_time,
	.find_record		= rt_plot_find_record,
};

void insert_vcpu(struct graph_info *ginfo, struct cont_list *cont,
		 struct vcpu_list *vcpu_info)
{
	struct graph_plot *plot;
	struct vcpu_info  *vcpu;
	char *label;

	vcpu = malloc_or_die(sizeof(*vcpu));
	vcpu->sid = vcpu_info->sid;
	vcpu->cont = cont;
	vcpu->label = malloc_or_die(LLABEL);

	vcpu->common.record_matches = rt_vcpu_plot_record_matches;
	vcpu->common.is_drawn = rt_vcpu_plot_is_drawn;
	vcpu->common.write_header = rt_vcpu_plot_write_header;

	g_assert(cont);

	label = malloc_or_die(1);
	snprintf(label, 2, " ");
	plot = trace_graph_plot_append(ginfo, label, PLOT_TYPE_SERVER_CPU,
				       TIME_TYPE_RT, &rt_vcpu_cb, vcpu);
	trace_graph_plot_add_all_recs(ginfo, plot);
}

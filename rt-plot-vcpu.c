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

static void update_task_label(struct vcpu_info *info, int tid, int tjob)
{
	info->fresh = FALSE;
	if (tid != info->task_tid) {
		info->task_tid = tid;
		snprintf(info->task_label, LLABEL, "%d:%d", tid, tjob);
	}
}

static void update_server_label(struct vcpu_info *info, int job)
{
	info->fresh = FALSE;
	if (job > info->server_job) {
		info->server_job = job;
		snprintf(info->server_label, LLABEL, "%d:%d",
			 info->sid, info->server_job);
	}
}

#define check_server(cond, vcpu, time, fmt, args...)			\
	do {								\
		if (!(cond)) fprintf(stderr, "%s -> %s: " fmt " at %llu\n", \
				     vcpu->server_label,		\
				     vcpu_info->task_label, ##args, time); \
	} while(0)

static int
try_server_switch_away(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		struct record *record, struct plot_info *info)
{
	int job, sid, tid, tjob, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_switch_away(ginfo, record,
						  &sid, &job,
						  &tid, &tjob, &ts);

	if (match && sid == vcpu_info->sid) {
		/* This server is no longer running something */
		update_task_label(vcpu_info, tid, tjob);
		update_server_label(vcpu_info, job);

		check_server(vcpu_info->server_running, vcpu_info, ts,
			     "switched away when server was not running");
		check_server(vcpu_info->task_running, vcpu_info, ts,
			     "switched away when no task was running");

		if (vcpu_info->task_run_time && vcpu_info->task_run_time < ts) {
			info->box = TRUE;
			info->bcolor = hash_pid(tid > 0 ? tid : -tid);
			info->bfill = vcpu_info->task_exec;
			info->bstart = vcpu_info->task_run_time;
			info->bend = ts;
			info->blabel = vcpu_info->task_label;
			info->flip = vcpu_info->show_server;
		}

		vcpu_info->task_run_time = 0ULL;
		vcpu_info->task_running = FALSE;
		vcpu_info->task_cpu = NO_CPU;

		ret = 1;
	} else if (vcpu_info->show_server && match && tid == vcpu_info->sid) {
		/* This server is no longer running */
		update_server_label(vcpu_info, tjob);

		check_server(vcpu_info->server_running, vcpu_info, ts,
			     "stopped running when wasn't running");
		check_server(!vcpu_info->task_running || vcpu_info->task_cpu == NO_CPU,
			     vcpu_info, ts, "stopped running while a task is active");

		if (vcpu_info->server_run_time && vcpu_info->server_run_time < ts) {
			info->box = TRUE;
			if (!sid)
				info->bcolor = 0;
			else
				info->bcolor = hash_cpu(sid - 1);
			info->bfill = TRUE;
			info->bstart = vcpu_info->server_run_time;
			info->bend = ts;
			info->blabel = vcpu_info->server_label;
		}
		vcpu_info->server_run_time = 0ULL;
		vcpu_info->server_cpu = NO_CPU;
		vcpu_info->server_running = FALSE;

		ret = 1;
	}

	if (ret) {
		dprintf(3, "VCPU Switch away tid: %d on %d:%d at %llu\n",
			tid, sid, job, ts);

		vcpu_info->task_run_time = 0ULL;
		vcpu_info->task_tid = -1;
		vcpu_info->task_running = FALSE;
		vcpu_info->task_cpu = NO_CPU;
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
	if (match && sid == vcpu_info->sid) {
		update_server_label(vcpu_info, job);
		check_server(!vcpu_info->task_running || vcpu_info->task_cpu == NO_CPU, vcpu_info, ts,
			     "started running %d:%d while another task ran",
			     tid, tjob);

		/* This server is now running something */
		update_task_label(vcpu_info, tid, tjob);

		check_server(vcpu_info->server_running, vcpu_info, ts,
			     "started running task without running server");

		vcpu_info->task_run_time = ts;
		vcpu_info->task_cpu = sid;
		vcpu_info->server_cpu = record->cpu;
		vcpu_info->task_tid = tid;
		vcpu_info->task_running = TRUE;
		ret = 1;
	} else if (vcpu_info->show_server && match && tid == vcpu_info->sid) {
		/* This server is now running */
		update_server_label(vcpu_info, tjob);

		check_server(vcpu_info->spare || !vcpu_info->server_running || vcpu_info->server_cpu == NO_CPU,
			     vcpu_info, ts, "running server again on %d:%d, run: %d, cpu: %d", sid, job, vcpu_info->server_running, vcpu_info->server_cpu);

		vcpu_info->spare = FALSE;

		vcpu_info->server_run_time = ts;
		vcpu_info->server_cpu = sid;
		vcpu_info->server_running = TRUE;
		ret = 1;
	}

	if (ret) {
		dprintf(3, "VCPU Switch to tid: %d on %d:%d at %llu\n",
			tid, sid, job, ts);
	}

	return ret;
}

static int try_switch_to(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
			 struct record *record, struct plot_info *info)
{
	int job, pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_switch_to(ginfo, record, &pid, &job, &ts);
	if (match && vcpu_info->task_run_time && pid &&
	    (pid == vcpu_info->task_tid || pid == -vcpu_info->task_tid)) {
		/* This server is running a physical task */
		if (pid == vcpu_info->task_tid)
			update_task_label(vcpu_info, pid, job);

		vcpu_info->task_exec = TRUE;

		/* Draw empty box for time spent not running a task */
		info->box = TRUE;
		info->flip = vcpu_info->show_server;
		info->bcolor = hash_pid(pid);
		info->bfill = FALSE;
		info->bstart = vcpu_info->task_run_time;
		info->bend = ts;
		info->blabel = vcpu_info->task_label;

		vcpu_info->task_run_time = ts;
		ret = 1;
	} else if (pid) {
		check_server(pid != vcpu_info->sid, vcpu_info, ts,
			     "server missing its task %d:%d, run time: %llu", pid, job, vcpu_info->task_run_time);
	}

	if (ret) {
		dprintf(3, "VCPU Switch away on VCPU %d for %d:%d at %llu\n",
			vcpu_info->sid, pid, job, ts);
	}
	return ret;
}

static int try_switch_away(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
			   struct record *record, struct plot_info *info)
{
	int job, pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_switch_away(ginfo, record, &pid, &job, &ts);
	if (match && pid && vcpu_info->task_exec &&
	    (pid == vcpu_info->task_tid || pid == -vcpu_info->task_tid)) {
		if (pid == vcpu_info->task_tid)
			update_task_label(vcpu_info, pid, job);

		/* This server is no longer running a real task */
		if (vcpu_info->task_run_time && vcpu_info->task_run_time < ts) {
			info->box = TRUE;
			info->flip = vcpu_info->show_server;
			info->bcolor = hash_pid(pid);
			info->bfill = TRUE;
			info->bstart = vcpu_info->task_run_time;
			info->bend = ts;
			info->blabel = vcpu_info->task_label;
		} else {
			dprintf(3, "Bad run time: %llu\n", vcpu_info->task_run_time);
		}

		vcpu_info->task_exec = FALSE;

		vcpu_info->task_run_time = ts;
		ret = 1;
	} else {
		check_server(pid != vcpu_info->sid, vcpu_info, ts,
			     "server missing its task switch away %d:%d, exec: %d", pid, job, vcpu_info->task_exec);
	}
	if (ret) {
		dprintf(3, "Switch away on VCPU %d for %d:%d at %llu\n",
			vcpu_info->sid, pid, job, ts);
	}
	return ret;
}

static int try_server_block(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		      struct record *record, struct plot_info *info)
{
	int sid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_block(ginfo, record, &sid, &ts);
	if (match && sid == vcpu_info->sid) {
		check_server(!vcpu_info->blocked || vcpu_info->block_cpu == NO_CPU,
			     vcpu_info, ts, "already blocked");
		check_server(!vcpu_info->server_running || vcpu_info->server_cpu == NO_CPU,
			     vcpu_info, ts,
			     "blocked before running stopped");

		vcpu_info->fresh = FALSE;
		vcpu_info->block_time = ts;
		vcpu_info->block_cpu = record->cpu;
		vcpu_info->blocked = TRUE;

		if (!ts)
			die("Initally no block time\n");

		dprintf(3, "Server block for %d on %d at %llu\n",
			sid, record->cpu, ts);
		ret = 1;
	}
	return ret;
}

static int try_server_resume(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
		      struct record *record, struct plot_info *info)
{
	int sid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_resume(ginfo, record, &sid, &ts);
	if (match && sid == vcpu_info->sid) {
		check_server(vcpu_info->blocked, vcpu_info, ts,
			     "resuming when not blocked");

		info->box = TRUE;
		info->bcolor = 0x0;
		info->bfill = TRUE;
		info->bthin = TRUE;
		info->bstart = vcpu_info->block_time;
		info->bend = ts;

		vcpu_info->fresh = FALSE;
		vcpu_info->block_time = 0ULL;
		vcpu_info->block_cpu = NO_CPU;
		vcpu_info->blocked = FALSE;

		dprintf(3, "Server resume for %d on %d at %llu\n",
			sid, record->cpu, ts);
		ret = 1;
	}
	return ret;
}

static int try_server_release(struct graph_info *ginfo,
			      struct vcpu_info *vcpu_info,
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

static int try_server_completion(struct graph_info *ginfo,
				 struct vcpu_info *vcpu_info,
				 struct record *record, struct plot_info *info)
{
	int sid, job, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_server_completion(ginfo, record, &sid, &job, &ts);
	if (match && (( vcpu_info->show_server && sid == vcpu_info->sid) ||
		      (!vcpu_info->show_server && sid == vcpu_info->task_tid))) {

		info->completion = TRUE;
		info->ctime = ts;

		dprintf(3, "VCPU completion for %d:%d on %d at %llu\n",
			sid, job, record->cpu, ts);
		ret = 1;
	}

	return ret;
}

/*
 * TODO: doesn't work with blocking
 */
static void do_plot_end(struct graph_info *ginfo, struct vcpu_info *vcpu_info,
			struct plot_info *info)
{
	int tid, job, tjob, is_running;
	struct record *record;

	if (ginfo->view_end_time == ginfo->end_time)
		return;

	if (vcpu_info->task_run_time && vcpu_info->task_cpu != NO_CPU) {
		/* The server was running something */
		info->box = TRUE;
		info->flip = vcpu_info->show_server;
		info->bcolor = hash_pid(vcpu_info->task_tid);
		info->bfill = vcpu_info->task_running;
		info->bstart = vcpu_info->task_run_time;
		info->bend = ginfo->view_end_time;
		info->blabel = vcpu_info->task_label;

		/* Might need to draw underbox as well */
		info->repeat = TRUE;

		vcpu_info->task_run_time = 0ULL;
		return;
	}

	if (vcpu_info->show_server && vcpu_info->server_run_time &&
	    vcpu_info->server_cpu != NO_CPU) {
		/* The server was running */
		info->box = TRUE;
		info->bcolor = hash_pid(vcpu_info->sid);
		info->bfill = TRUE;
		info->bstart = vcpu_info->server_run_time;
		info->bend = ginfo->view_end_time;
		info->blabel = vcpu_info->server_label;
		vcpu_info->server_run_time = 0ULL;
		return;
	}

	if (vcpu_info->show_server && vcpu_info->block_time &&
	    vcpu_info->block_cpu != NO_CPU) {
		/* The server was running */
		/* Blocking happened */
		info->box = TRUE;
		info->bcolor = 0x0;
		info->bfill = TRUE;
		info->bthin = TRUE;
		info->bstart = vcpu_info->block_time;
		info->bend = ginfo->view_end_time;
		vcpu_info->fresh = FALSE;
		vcpu_info->block_cpu = NO_CPU;
		vcpu_info->block_time = 0ULL;
		return;
	}

	if (vcpu_info->fresh) {
		/* No records received. Get information about time */
		is_running = get_server_info(ginfo,
					     (struct rt_plot_common*)vcpu_info,
					     vcpu_info->sid,
					     ginfo->view_end_time,
					     &job, &tid, &tjob, &record);
		if (is_running) {
			update_task_label(vcpu_info, tid, tjob);
			update_server_label(vcpu_info, job);

			vcpu_info->task_tid = tid;
			vcpu_info->task_running =
				is_task_running(ginfo, ginfo->view_end_time, tid);
			vcpu_info->server_run_time = ginfo->view_start_time;

			do_plot_end(ginfo, vcpu_info, info);
		}
	}
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
		try_server_release(ginfo, vcpu_info, record, info) ||
		try_server_completion(ginfo, vcpu_info, record, info) ||
		try_switch_to(ginfo, vcpu_info, record, info) ||
		try_switch_away(ginfo, vcpu_info, record, info) ||
		try_server_block(ginfo, vcpu_info, record, info) ||
		try_server_resume(ginfo, vcpu_info, record, info);
	return match;
}
static void rt_vcpu_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
			       unsigned long long time)
{
	struct vcpu_info *vcpu_info = plot->private;

	vcpu_info->task_tid = -1;
	vcpu_info->task_run_time = time;
	vcpu_info->task_running = TRUE;
	vcpu_info->task_exec = TRUE;
	vcpu_info->task_cpu = NO_CPU;

	vcpu_info->server_job = -1;
	vcpu_info->server_run_time = time;
	vcpu_info->server_cpu = NO_CPU;
	vcpu_info->server_running = TRUE;
	vcpu_info->spare = TRUE;

	vcpu_info->block_time = time;
	vcpu_info->block_cpu  = NO_CPU;
	vcpu_info->blocked    = TRUE;

	vcpu_info->fresh = TRUE;

	update_task_label(vcpu_info, 0, 0);
	update_server_label(vcpu_info, 0);
}

static void rt_vcpu_plot_destroy(struct graph_info *ginfo, struct graph_plot *plot)
{
	struct vcpu_info *vcpu_info = plot->private;
	trace_graph_plot_remove_all_recs(ginfo, plot);
	free(vcpu_info->task_label);
	free(vcpu_info->server_label);
	free(vcpu_info);
}

/**
 * Return 1 if @record is relevant to @match_sid.
 */
int rt_vcpu_plot_record_matches(struct rt_plot_common *rt,
				       struct graph_info *ginfo,
				       struct record *record)
{
	struct vcpu_info *vcpu_info = (struct vcpu_info*)rt;
	int dint, sid, match;
	unsigned long long dull;

#define ARG ginfo, record, &sid, &dint
	match = rt_graph_check_server_switch_to(ARG, &dint, &dint, &dull)   ||
		rt_graph_check_server_switch_away(ARG,&dint, &dint, &dull)  ||
		rt_graph_check_server_completion(ARG, &dull)  		    ||
		rt_graph_check_server_release(ARG, &dull, &dull)            ||
		rt_graph_check_switch_to(ARG, &dull)                        ||
		rt_graph_check_switch_away(ARG, &dull);
#undef ARG
	return (match && (sid == vcpu_info->sid || -sid == vcpu_info->sid));
}

static int
rt_vcpu_plot_is_drawn(struct graph_info *ginfo, int eid)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	return (eid == rtg_info->server_switch_to_id   ||
		eid == rtg_info->server_switch_away_id ||
		eid == rtg_info->server_release_id     ||
		eid == rtg_info->server_completion_id  ||
		eid == rtg_info->switch_to_id          ||
		eid == rtg_info->switch_away_id);
}

static struct record*
rt_vcpu_plot_write_header(struct rt_plot_common *rt,
			  struct graph_info *ginfo,
			  struct trace_seq *s,
			  unsigned long long time)
{
	int is_running, job = 0, tid, tjob;
	struct vcpu_info *vcpu_info = (struct vcpu_info*)rt;
	struct record *record;

	is_running = get_server_info(ginfo, rt, vcpu_info->sid, time,
				     &job, &tid, &tjob, &record);

	trace_seq_printf(s, "%s\nServer: %d:%d\n", vcpu_info->cont->name,
			 vcpu_info->sid, job);

	if (is_running) {
		trace_seq_printf(s, "Running:  %d:%d", tid, tjob);
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
	int len;

	vcpu = malloc_or_die(sizeof(*vcpu));
	vcpu->sid = vcpu_info->sid;
	vcpu->cont = cont;
	vcpu->server_label = malloc_or_die(LLABEL);
	vcpu->task_label = malloc_or_die(LLABEL);

	vcpu->common.record_matches = rt_vcpu_plot_record_matches;
	vcpu->common.is_drawn = rt_vcpu_plot_is_drawn;
	vcpu->common.write_header = rt_vcpu_plot_write_header;

	g_assert(cont);

	len = strlen(cont->name) + 100;
	label = malloc_or_die(len);

	if (vcpu_info->params.wcet) {
		vcpu->show_server = TRUE;
		snprintf(label, len, "%s-%d\n(%1.1f, %1.1f)",
			 cont->name, -vcpu_info->sid,
			 nano_as_milli(vcpu_info->params.wcet),
			 nano_as_milli(vcpu_info->params.period));
	} else {
		/* Always running, no need to see the server */
		vcpu->show_server = TRUE;
		snprintf(label, len, "%s-%d",
			 cont->name, -vcpu_info->sid);
	}

	plot = trace_graph_plot_append(ginfo, label, PLOT_TYPE_SERVER_CPU,
				       TIME_TYPE_RT, &rt_vcpu_cb, vcpu);
	trace_graph_plot_add_all_recs(ginfo, plot);
}

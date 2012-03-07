#include "trace-graph.h"

#define LLABEL 30

#define DEBUG_LEVEL	4
#if DEBUG_LEVEL > 0
#define dprintf(l, x...)			\
	do {					\
		if (l <= DEBUG_LEVEL)		\
			printf(x);		\
	} while (0)
#else
#define dprintf(l, x...)	do { if (0) printf(x); } while (0)
#endif

/*
 * Extract timestamp from a record, attempting to use cache if possible
 */
static unsigned long long
get_rts(struct graph_info *ginfo, struct record *record)
{
	gint epid;
	unsigned long long ts;
	if (!record->cached_rts) {
		rt_graph_check_any(&ginfo->rtinfo, ginfo->pevent, record,
				   &epid, &ts);
		record->cached_rts = ts;
	} else
		ts = record->cached_rts;
	return ts;
}

/*
 * Get the real-time timestamp of the next record at time
 */
static unsigned long long
next_rts(struct graph_info *ginfo, int cpu, unsigned long long time)
{
	struct record *record;
	unsigned long long ts;
	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);
	record = tracecmd_read_data(ginfo->handle, cpu);
	if (record) {
		ts = get_rts(ginfo, record);
		free_record(record);
		return ts;
	} else
		return 0;
}

static void set_cpu_to_time(int cpu, struct graph_info *ginfo, unsigned long long time)
{
	struct record *record;
	unsigned long long rts, seek_time, last_seek;
	long long diff;

	rts = next_rts(ginfo, cpu, time);
	diff = time - rts;

	/* "Guess" a new target based on difference */
	seek_time = time + diff;
	rts = next_rts(ginfo, cpu, seek_time);
	diff = time - rts;

	/* Zero in in 1.5x the difference increments */
	if (rts && diff > 0) {
		/*   rts       time
		 *   seek        ?
		 * ---|---->>----|---
		 */
		do {
			last_seek = seek_time;
			seek_time = seek_time + 1.5 * (time - rts);
			rts = next_rts(ginfo, cpu, seek_time);
		} while (rts < time);
		tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, last_seek);
		seek_time = last_seek;
	} else if (rts && diff < 0) {
		/*   time      rts
		 *    ?        seek
		 * ---|----<<----|---
		 */
		do {
			seek_time = seek_time - 1.5 * (rts - time);
			rts = next_rts(ginfo, cpu, seek_time);
		} while (rts > time);
	}

	/* Get to first record at or after time */
	while ((record = tracecmd_read_data(ginfo->handle, cpu))) {
		if (get_rts(ginfo, record) >= time)
			break;
		free_record(record);
	}
	if (record) {
		tracecmd_set_cursor(ginfo->handle, cpu, record->offset);
		free_record(record);
	} else
		tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, seek_time);
}

void set_cpus_to_time(struct graph_info *ginfo, unsigned long long time)
{
	int cpu;
	for (cpu = 0; cpu < ginfo->cpus; cpu++)
		set_cpu_to_time(cpu, ginfo, time);
}

static gboolean record_matches_pid(struct graph_info *ginfo,
				   struct record *record,
				   int match_pid)
{
	gint dint, pid = 0, match = 0;
	unsigned long long dull;
	struct rt_graph_info *rtg_info = &ginfo->rtinfo;

	/* Must use check_* in case record has not been found yet,
	 * this macro was the best of many terrible options
	 */
#define MARGS rtg_info, ginfo->pevent, record, &pid
	match = rt_graph_check_switch_to(MARGS, &dint, &dull)           ||
		rt_graph_check_switch_away(MARGS, &dint,  &dull)        ||
		rt_graph_check_task_release(MARGS, &dint, &dull, &dull) ||
		rt_graph_check_task_completion(MARGS, &dint, &dull)     ||
		rt_graph_check_task_block(MARGS, &dull)                 ||
		rt_graph_check_task_resume(MARGS, &dull)		||
		rt_graph_check_any(MARGS, &dull);
#undef MARGS
	return match && pid == match_pid;
}

struct record*
find_record(struct graph_info *ginfo, gint pid, guint64 time)
{
	int next_cpu, match;
	struct record *record = NULL;

	set_cpus_to_time(ginfo, time);
	do {
		free_record(record);
		record = tracecmd_read_next_data(ginfo->handle, &next_cpu);
		if (!record)
			return NULL;
		match = record_matches_pid(ginfo, record, pid);
	} while (!(get_rts(ginfo, record) > time && match));

	return record;
}

/*
 * Update current job in @rtt_info, ensuring monotonic increase
 */
static int update_job(struct rt_task_info *rtt_info, int job)
{
	if (job < rtt_info->last_job) {
		printf("Inconsistent job state for %d:%d -> %d\n",
		    rtt_info->base.pid, rtt_info->last_job, job);
		return 0;
	} else if (job > rtt_info->last_job) {
		rtt_info->last_job = job;
		snprintf(rtt_info->label, LLABEL, "%d:%d",
			 rtt_info->base.pid, rtt_info->last_job);
	}
	return 1;
}

static int try_param(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		     struct record *record, struct plot_info *info)
{
	int pid, match, ret = 0;
	unsigned long long wcet, period;

	/* Only 1 param record per event */
	if (rtt_info->params_found)
		goto out;

	match = rt_graph_check_task_param(&ginfo->rtinfo, ginfo->pevent,
					  record, &pid, &wcet, &period);
	if (match && pid == rtt_info->base.pid) {
		update_job(rtt_info, 0);
		rtt_info->wcet = wcet;
		rtt_info->period = period;
		rtt_info->params_found = TRUE;
		ret = 1;
	}
 out:
	return ret;
}


static int try_release(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		       struct record *record, struct plot_info *info)
{
	int pid, job, match, ret = 0;
	unsigned long long release, deadline;

	match = rt_graph_check_task_release(&ginfo->rtinfo, ginfo->pevent,
					    record, &pid, &job,
					    &release, &deadline);
	if (match && pid == rtt_info->base.pid) {
		update_job(rtt_info, job);
		info->release = TRUE;
		info->rtime = release;
		info->rlabel = rtt_info->label;

		info->deadline = TRUE;
		info->dtime = deadline;
		info->dlabel = rtt_info->label;

		ret = 1;
	}
	return ret;
}

static int try_completion(struct graph_info *ginfo,
			  struct rt_task_info *rtt_info,
			  struct record *record, struct plot_info *info)
{
	int pid, job, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_task_completion(&ginfo->rtinfo, ginfo->pevent,
					       record, &pid, &job, &ts);
	if (match && pid == rtt_info->base.pid) {
		update_job(rtt_info, job);
		info->completion = TRUE;
		info->ctime = ts;
		info->clabel = rtt_info->label;
		ret = 1;
	}
	return ret;
}

static int try_block(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		     struct record *record, struct plot_info *info)
{
	int pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_task_block(&ginfo->rtinfo, ginfo->pevent,
					  record, &pid, &ts);
	if (match && pid == rtt_info->base.pid) {
		rtt_info->block_time = ts;
		ret = 1;
	}
	return ret;
}

static int try_resume(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		      struct record *record, struct plot_info *info)
{
	int pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_task_resume(&ginfo->rtinfo, ginfo->pevent,
					   record, &pid, &ts);
	if (match && pid == rtt_info->base.pid) {
		info->box = TRUE;
		info->bcolor = 0x0;
		info->bfill = TRUE;
		info->bthin = TRUE;
		info->bstart = rtt_info->block_time;
		info->bend = ts;

		rtt_info->block_time = 0ULL;

		ret = 1;
	}
	return ret;
}

static unsigned long long
try_switch_away(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		struct record *record, struct plot_info *info)
{
	int job, pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_switch_away(&ginfo->rtinfo, ginfo->pevent,
					   record, &pid, &job, &ts);
	if (match && pid == rtt_info->base.pid) {
		update_job(rtt_info, job);

		if (rtt_info->run_time && rtt_info->run_time < ts) {
			dprintf(3, "Box for %d:%d, %llu to %llu on CPU %d\n",
				rtt_info->base.pid, rtt_info->last_job,
				rtt_info->run_time, ts, rtt_info->last_cpu);
			info->box = TRUE;
			info->bcolor = hash_cpu(rtt_info->last_cpu);
			info->bfill = TRUE;
			info->bstart = rtt_info->run_time;
			info->bend = ts;
			info->blabel = rtt_info->label;
		}

		rtt_info->run_time = 0ULL;
		rtt_info->last_cpu = -1;

		ret = 1;
	}
	return ret;
}

static int try_switch_to(struct graph_info *ginfo, struct rt_task_info *rtt_info,
			 struct record *record, struct plot_info *info)
{
	int job, pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_switch_to(&ginfo->rtinfo, ginfo->pevent,
					 record, &pid, &job, &ts);
	if (match && pid == rtt_info->base.pid) {
		update_job(rtt_info, job);

		rtt_info->run_time = ts;
		rtt_info->last_cpu = record->cpu;

		dprintf(3, "Switching to %d:%d at %llu on CPU %d\n",
			rtt_info->base.pid, rtt_info->last_job,
			ts, rtt_info->last_cpu);

		ret = 1;
	}
	return ret;
}

static int try_other(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		   struct record *record, struct plot_info *info)
{
	int pid, epid, ret = 0;
	unsigned long long ts;
	struct task_plot_info *task_info = &rtt_info->base;

	pid = task_info->pid;
	rt_graph_check_any(&ginfo->rtinfo, ginfo->pevent, record, &epid, &ts);

	if (pid == epid || record->cpu == rtt_info->last_cpu) {
		info->line = TRUE;
		info->lcolor = hash_pid(record->cpu);
		info->ltime = ts;
		ret = 1;
	}

	return ret;
}

/*
 * Find the information for the last release of @rtt_info on @cpu before @time.
 * @min_ts: the minimum time stamp to parse
 *
 * Returns release record and @out_job, @out_release, and @out_deadline if a
 * release was found after @mints matching @time.
 */
static struct record*
get_previous_release(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		     int cpu,
		     unsigned long long min_ts, unsigned long long time,
		     int *out_job,
		     unsigned long long *out_release,
		     unsigned long long *out_deadline)
{
	int pid, job, match;
	unsigned long long release, deadline;
	struct record *last_record, *record, *ret = NULL;
	struct rt_graph_info *rtg_info = &ginfo->rtinfo;

	last_record = tracecmd_peek_data(ginfo->handle, cpu);
	if (!last_record)
		return NULL;
	last_record->ref_count++;

	while ((record = tracecmd_read_prev(ginfo->handle, last_record))) {
		if (record->ts < min_ts) {
			free_record(record);
			goto out;
		}
		match = rt_graph_check_task_release(rtg_info, ginfo->pevent,
						    record, &pid, &job,
						    &release, &deadline);
		free_record(last_record);
		last_record = record;
		if (match && (pid == rtt_info->base.pid) && release <= time) {
			ret = record;
			last_record = NULL;
			*out_job = job;
			*out_release = release;
			*out_deadline = deadline;
			break;
		}
	};
 out:
	free_record(last_record);
	return ret;
}

/*
 * Return information for @time, returns @job, @release, @deadline, and @record.
 * @job: Job number at this time
 * @release: Job's release time
 * @deadline: Job's deadline
 * @record: Matching record
 */
static int get_time_info(struct graph_info *ginfo,
			 struct rt_task_info *rtt_info,
			 unsigned long long time,
			 int *out_job,
			 unsigned long long *out_release,
			 unsigned long long *out_deadline,
			 struct record **out_record)

{
	int cpu, job;
	unsigned long long release, deadline, min_ts;
	struct record *record;
	struct offset_cache *offsets;

	/* Seek CPUs to first record after this time */
	*out_record = find_record(ginfo, rtt_info->base.pid, time);
	if (!*out_record)
		goto out;

	min_ts = time - 2*rtt_info->wcet;
	*out_job = 0;
	*out_release = 0;
	*out_deadline = 0;

	offsets = save_offsets(ginfo);
	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		record = get_previous_release(ginfo, rtt_info, cpu, min_ts,
					      time, &job, &release, &deadline);
		if (record && record->ts > min_ts) {
			*out_job = job;
			*out_release = release;
			*out_deadline = deadline;
			min_ts = record->ts;
		}
		free_record(record);
	}
	restore_offsets(ginfo, offsets);
 out:
	return (min_ts == 0);
}

static inline int in_res(struct graph_info *ginfo, unsigned long long time,
			 unsigned long target)
{
	return  time > target - 2/ginfo->resolution &&
		time < target + 2/ginfo->resolution;
}

static int rt_task_plot_event(struct graph_info *ginfo, struct graph_plot *plot,
			      struct record *record, struct plot_info *info)
{
	struct rt_task_info *rtt_info = plot->private;
	struct task_plot_info *task_info = &rtt_info->base;
	int match, cpu;

	/* No more records, finish what we started */
	if (!record) {
		update_last_task_record(ginfo, task_info, record);
		if (task_info->last_cpu >= 0) {
			info->box = TRUE;
			info->bstart = task_info->last_time;
			info->bend = ginfo->view_end_time;
			info->bcolor = hash_cpu(task_info->last_cpu);
		}
		for (cpu = 0; cpu < ginfo->cpus; cpu++) {
			free_record(task_info->last_records[cpu]);
			task_info->last_records[cpu] = NULL;
		}
		return 0;
	}

	match = try_param(ginfo, rtt_info, record, info)       ||
		try_switch_away(ginfo, rtt_info, record, info) ||
		try_switch_to(ginfo, rtt_info, record, info)   ||
		try_release(ginfo, rtt_info, record, info)     ||
		try_completion(ginfo, rtt_info, record, info)  ||
		try_block(ginfo, rtt_info, record, info)       ||
		try_resume(ginfo, rtt_info, record, info)      ||
		try_other(ginfo, rtt_info, record, info);

	/* This record is neither on our CPU nor related to us, useless */
	if (!match && record->cpu != task_info->last_cpu) {
		if (!task_info->last_records[record->cpu]) {
			task_info->last_records[record->cpu] = record;
			tracecmd_record_ref(record);
		}
		return 0;
	}

	if (!match) {
		cpu = record->cpu;
		/* We need some record, use this if none exist */
		if (!task_info->last_records[cpu]) {
			free_record(task_info->last_records[cpu]);
			task_info->last_records[cpu] = record;
		}
	} else {
		update_last_task_record(ginfo, task_info, record);
	}

	return 1;
}

static void rt_task_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
			       unsigned long long time)
{
	struct rt_task_info *rtt_info = plot->private;

	task_plot_start(ginfo, plot, time);

	rtt_info->wcet = 0ULL;
	rtt_info->period = 0ULL;
	rtt_info->run_time = 0ULL;
	rtt_info->block_time = 0ULL;
	rtt_info->last_cpu = -1;
	rtt_info->last_job = -1;
	rtt_info->params_found = FALSE;
	update_job(rtt_info, 0);
}

static void rt_task_plot_destroy(struct graph_info *ginfo, struct graph_plot *plot)
{
	struct rt_task_info *rtt_info = plot->private;
	printf("Destroying plot %d\n", rtt_info->base.pid);
	free(rtt_info->label);
	task_plot_destroy(ginfo, plot);
}

static int rt_task_plot_display_last_event(struct graph_info *ginfo,
				 struct graph_plot *plot,
				 struct trace_seq *s,
				 unsigned long long time)
{
	int eid;
	struct event_format *event;
	struct record *record;
	struct offset_cache *offsets;
	struct rt_task_info *rtt_info = plot->private;

	offsets = save_offsets(ginfo);
	record = find_record(ginfo, rtt_info->base.pid, time);
	restore_offsets(ginfo, offsets);
	if (!record)
		return 0;

	eid = pevent_data_type(ginfo->pevent, record);
	event = pevent_data_event_from_type(ginfo->pevent, eid);
	if (event)
		trace_seq_puts(s, event->name);
	else
		trace_seq_printf(s, "UNKNOWN EVENT %d\n", eid);
	trace_seq_putc(s, '\n');
	trace_seq_printf(s, "CPU %d\n", record->cpu);
	free_record(record);

	return 1;
}

static int rt_task_plot_display_info(struct graph_info *ginfo,
			  struct graph_plot *plot,
			  struct trace_seq *s,
			  unsigned long long time)
{
	const char *comm;
	int show_dead, show_rel, pid, job, eid;
	struct record *record;
	struct event_format *event;
	unsigned long usec, sec;
	unsigned long long release, deadline, rts;
	struct rt_task_info *rtt_info = plot->private;
	struct offset_cache *offsets;

	offsets = save_offsets(ginfo);
	get_time_info(ginfo, rtt_info, time,
		      &job, &release, &deadline, &record);
	restore_offsets(ginfo, offsets);
	show_rel  = in_res(ginfo, release, time);
	show_dead = in_res(ginfo, deadline, time);

	/* Show real-time data about time */
	pid = rtt_info->base.pid;
	comm = pevent_data_comm_from_pid(ginfo->pevent, pid);
	trace_seq_printf(s, "%s - %d:%d\n", comm, pid, job);
	if (show_rel)
		trace_seq_printf(s, "RELEASE\n");
	if (show_dead)
		trace_seq_printf(s, "DEADLINE\n");

	if (record) {
		rts = get_rts(ginfo, record);
		if (in_res(ginfo, rts, time)) {
			eid = pevent_data_type(ginfo->pevent, record);
			event = pevent_data_event_from_type(ginfo->pevent, eid);
			if (event) {
				trace_seq_puts(s, event->name);
				trace_seq_putc(s, '\n');
				pevent_event_info(s, event, record);
				trace_seq_putc(s, '\n');
			} else
				trace_seq_printf(s, "UNKNOWN EVENT %d\n", eid);
		}
		convert_nano(get_rts(ginfo, record), &sec, &usec);
		trace_seq_printf(s, "%lu.%06lu CPU: %03d",
				 sec, usec, record->cpu);
		free_record(record);
	}

	return 1;
}

static const struct plot_callbacks rt_task_cb = {
	.plot_event		= rt_task_plot_event,
	.start			= rt_task_plot_start,
	.destroy		= rt_task_plot_destroy,

	.display_last_event	= rt_task_plot_display_last_event,
	.display_info		= rt_task_plot_display_info,

	.match_time		= task_plot_match_time,
	.find_record		= task_plot_find_record,
};

void rt_plot_task_update_callback(gboolean accept,
				  gint *selected,
				  gint *non_select,
				  gpointer data)
{
	graph_tasks_update_callback(TASK_PLOT_RT, rt_plot_task,
				    accept, selected, non_select, data);
}

void rt_plot_task_plotted(struct graph_info *ginfo, gint **plotted)
{
	graph_tasks_plotted(ginfo, TASK_PLOT_RT, plotted);
}

void rt_plot_task(struct graph_info *ginfo, int pid, int pos)
{
	struct rt_graph_info *rtinfo = &ginfo->rtinfo;
	struct rt_task_info *rtt_info;
	struct graph_plot *plot;
	const char *comm;
	char *label;
	int len;

	if (!find_task_list(rtinfo->tasks, pid))
		die("Cannot create RT plot of non-RT task %d!\n", pid);

	rtt_info = malloc_or_die(sizeof(*rtt_info));
	rtt_info->label = malloc_or_die(LLABEL);

	init_task_plot_info(ginfo, &rtt_info->base, TASK_PLOT_RT, pid);

	comm = pevent_data_comm_from_pid(ginfo->pevent, pid);
	len = strlen(comm) + 100;
	label = malloc_or_die(len);
	snprintf(label, len, "*%s-%d", comm, pid);
	rtt_info->pid = pid;

	printf("Created plot for %s-%d / %d %p\n", comm, pid, rtt_info->base.pid,
	       rtt_info);

	plot = trace_graph_plot_insert(ginfo, pos, label, PLOT_TYPE_TASK,
				       &rt_task_cb, rtt_info);
	free(label);

	trace_graph_plot_add_all_recs(ginfo, plot);
}

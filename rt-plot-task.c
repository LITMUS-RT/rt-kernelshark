#include "trace-graph.h"
#include "trace-filter.h"

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

/*
 * Return 1 if @record is relevant to @match_pid.
 */
static gboolean record_matches_pid(struct graph_info *ginfo,
				   struct record *record,
				   int match_pid)
{
	gint dint, pid = 0, match;
	unsigned long long dull;
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;

	/* Must use check_* in case record has not been found yet,
	 * this macro was the best of many terrible options.
	 */
#define ARG rtg_info, ginfo->pevent, record, &pid
	match = rt_graph_check_switch_to(ARG, &dint, &dull)           ||
		rt_graph_check_switch_away(ARG, &dint,  &dull)        ||
		rt_graph_check_task_release(ARG, &dint, &dull, &dull) ||
		rt_graph_check_task_completion(ARG, &dint, &dull)     ||
		rt_graph_check_task_block(ARG, &dull)                 ||
		rt_graph_check_task_resume(ARG, &dull)		||
		rt_graph_check_any(ARG, &dint, &dull);
#undef ARG
	return pid == match_pid;
}

/*
 * Return the first record after @time (within a range) which draws a box.
 */
static struct record*
next_box_record(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		  unsigned long long time, int *out_eid)
{
	struct record *record = NULL, *ret = NULL;
	struct pevent *pevent;
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	unsigned long long dull, max_ts;
	int match, pid, eid, dint, cpu;

	*out_eid = 0;
	pevent = ginfo->pevent;
	max_ts = ginfo->view_end_time +
		SEARCH_PERIODS * rtg_info->max_period;
	set_cpus_to_rts(ginfo, time);
	while ((record = tracecmd_read_next_data(ginfo->handle, &cpu))) {
		if (get_rts(ginfo, record) > max_ts) {
			free_record(record);
			break;
		}

		/* Sorry mother */
#define ARG rtg_info, pevent, record, &pid
		match = rt_graph_check_switch_to(ARG, &dint, &dull)   ||
			rt_graph_check_switch_away(ARG, &dint, &dull) ||
			rt_graph_check_task_block(ARG, &dull)        ||
			rt_graph_check_task_resume(ARG, &dull);
#undef ARG
		eid = (match) ? pevent_data_type(pevent, record) : 0;

		if (eid && pid == rtt_info->pid) {
			ret = record;
			*out_eid = eid;
			break;
		}
		free_record(record);
	};
	return ret;
}

/*
 * Return first relevant record after @time.
 * @display: If set, only considers records which are plotted in some way
 */
static struct record*
__find_record(struct graph_info *ginfo, gint pid, guint64 time, int display)
{
	int next_cpu, match, eid, ignored= 0;
	struct record *record = NULL;
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;

	set_cpus_to_rts(ginfo, time);
	do {
		free_record(record);
		record = tracecmd_read_next_data(ginfo->handle, &next_cpu);
		if (!record)
			return NULL;
		match = record_matches_pid(ginfo, record, pid);
		if (display) {
			eid = pevent_data_type(ginfo->pevent, record);
			ignored = (eid == rtg_info->switch_away_id ||
				   eid == rtg_info->switch_to_id   ||
				   eid == rtg_info->task_completion_id ||
				   eid == rtg_info->task_block_id  ||
				   eid == rtg_info->task_resume_id ||
				   eid == rtg_info->task_release_id);
		}
		ignored = ignored && eid == ginfo->event_sched_switch_id;
	} while (!(get_rts(ginfo, record) > time && match && !ignored));

	return record;
}

static inline struct record*
find_record(struct graph_info *ginfo, gint pid, guint64 time)
{
	return __find_record(ginfo, pid, time, 0);
}

static inline struct record*
find_display_record(struct graph_info *ginfo, gint pid, guint64 time)
{
	return __find_record(ginfo, pid, time, 1);
}

/*
 * Update current job in @rtt_info, ensuring monotonic increase.
 */
static int update_job(struct rt_task_info *rtt_info, int job)
{
	rtt_info->fresh = FALSE;
	if (job < rtt_info->last_job) {
		printf("Inconsistent job state for %d:%d -> %d\n",
		    rtt_info->pid, rtt_info->last_job, job);
		return 0;
	} else if (job > rtt_info->last_job) {
		rtt_info->last_job = job;
		snprintf(rtt_info->label, LLABEL, "%d:%d",
			 rtt_info->pid, rtt_info->last_job);
	}
	return 1;
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
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;

	last_record = tracecmd_peek_data(ginfo->handle, cpu);
	*out_job = *out_release = *out_deadline = 0;
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
		if (match && (pid == rtt_info->pid) && release <= time) {
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
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;

	/* Seek CPUs to first record after this time */
	*out_job = *out_release = *out_deadline = 0;
	*out_record = find_record(ginfo, rtt_info->pid, time);
	if (!*out_record)
		return 0;

	/* This is not necessarily correct for sporadic, but will do for now */
	if (time < rtt_info->first_rels[2]) {
		job = (time >= rtt_info->first_rels[1]) ? 2 : 1;
		*out_job = job;
		*out_release = rtt_info->first_rels[job - 1];
		*out_deadline = rtt_info->first_rels[job];
		goto out;
	}

	min_ts = time - SEARCH_PERIODS * rtg_info->max_period;
	*out_job = *out_release = *out_deadline = 0;

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

	match = rt_graph_check_task_param(&ginfo->rtg_info, ginfo->pevent,
					  record, &pid, &wcet, &period);
	if (match && pid == rtt_info->pid) {
		update_job(rtt_info, 0);
		rtt_info->wcet = wcet;
		rtt_info->period = period;
		rtt_info->params_found = TRUE;
		ret = 1;
		rtt_info->first_rels[0] = get_rts(ginfo, record);
		dprintf(3, "Params for %d (%llu, %llu)\n on %d",
			pid, wcet, period, record->cpu);
	}
 out:
	return ret;
}


static int try_release(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		       struct record *record, struct plot_info *info)
{
	int pid, job, match, ret = 0;
	unsigned long long release, deadline;

	match = rt_graph_check_task_release(&ginfo->rtg_info, ginfo->pevent,
					    record, &pid, &job,
					    &release, &deadline);
	if (match && pid == rtt_info->pid) {
		update_job(rtt_info, job);

		info->release = TRUE;
		info->rtime = release;

		info->deadline = TRUE;
		info->dtime = deadline;

		if (job <= 3)
			rtt_info->first_rels[job - 1] = release;

		dprintf(3, "Release for %d:%d on %d, rel: %llu, dead: %llu\n",
			pid, job, record->cpu, release, deadline);

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

	match = rt_graph_check_task_completion(&ginfo->rtg_info, ginfo->pevent,
					       record, &pid, &job, &ts);
	if (match && pid == rtt_info->pid) {
		update_job(rtt_info, job);
		info->completion = TRUE;
		info->ctime = ts;
		dprintf(3, "Completion for %d:%d on %d at %llu\n",
			pid, job, record->cpu, ts);
		ret = 1;
	}
	return ret;
}

static int try_block(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		     struct record *record, struct plot_info *info)
{
	int pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_task_block(&ginfo->rtg_info, ginfo->pevent,
					  record, &pid, &ts);
	if (match && pid == rtt_info->pid) {
		rtt_info->fresh = FALSE;
		rtt_info->block_time = ts;
		rtt_info->block_cpu = NO_CPU;
		dprintf(3, "Resume for %d on %d at %llu\n",
			pid, record->cpu, ts);
		ret = 1;
	}
	return ret;
}

static int try_resume(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		      struct record *record, struct plot_info *info)
{
	int pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_task_resume(&ginfo->rtg_info, ginfo->pevent,
					   record, &pid, &ts);
	if (match && pid == rtt_info->pid) {
		info->box = TRUE;
		info->bcolor = 0x0;
		info->bfill = TRUE;
		info->bthin = TRUE;
		info->bstart = rtt_info->block_time;
		info->bend = ts;
		rtt_info->fresh = FALSE;

		rtt_info->block_time = 0ULL;
		rtt_info->block_cpu = NO_CPU;
		dprintf(3, "Resume for %d on %d at %llu\n",
			pid, record->cpu, ts);

		ret = 1;
	}
	return ret;
}

static int
try_switch_away(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		struct record *record, struct plot_info *info)
{
	int job, pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_switch_away(&ginfo->rtg_info, ginfo->pevent,
					   record, &pid, &job, &ts);
	if (match && pid == rtt_info->pid) {
		update_job(rtt_info, job);

		if (rtt_info->run_time && rtt_info->run_time < ts) {
			dprintf(3, "Box for %d:%d, %llu to %llu on CPU %d\n",
				rtt_info->pid, rtt_info->last_job,
				rtt_info->run_time, ts, record->cpu);
			info->box = TRUE;
			info->bcolor = hash_cpu(record->cpu);
			info->bfill = TRUE;
			info->bstart = rtt_info->run_time;
			info->bend = ts;
			info->blabel = rtt_info->label;
		}

		dprintf(3, "Switch away for %d:%d on %d at %llu\n",
			pid, job, record->cpu, ts);
		rtt_info->run_time = 0ULL;
		rtt_info->run_cpu = NO_CPU;

		ret = 1;
	}
	return ret;
}

static int try_switch_to(struct graph_info *ginfo, struct rt_task_info *rtt_info,
			 struct record *record, struct plot_info *info)
{
	int job, pid, match, ret = 0;
	unsigned long long ts;

	match = rt_graph_check_switch_to(&ginfo->rtg_info, ginfo->pevent,
					 record, &pid, &job, &ts);
	if (match && pid == rtt_info->pid) {
		update_job(rtt_info, job);
		rtt_info->run_time = ts;
		rtt_info->run_cpu = record->cpu;
		dprintf(3, "Switch to for %d:%d on %d at %llu\n",
			pid, job, record->cpu, ts);
		ret = 1;
	}
	return ret;
}

static int try_other(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		   struct record *record, struct plot_info *info)
{
	int pid, eid, epid, my_pid, my_cpu, not_sa, ret = 0;
	unsigned long long ts;

	pid = rtt_info->pid;
	rt_graph_check_any(&ginfo->rtg_info, ginfo->pevent, record,
			   &epid, &eid, &ts);

	my_pid = (pid == epid);
	my_cpu = (rtt_info->run_time && record->cpu == rtt_info->run_cpu);
	not_sa = (eid != ginfo->rtg_info.switch_away_id);
	if (not_sa && (my_pid || my_cpu) &&
	    eid != ginfo->event_sched_switch_id) {
		info->line = TRUE;
		info->lcolor = hash_pid(record->cpu);
		info->ltime = ts;
		ret = 1;
	}

	return ret;
}

static void do_plot_end(struct graph_info *ginfo, struct rt_task_info *rtt_info,
			struct plot_info *info)
{
	struct record *record;
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	int eid;

	if (rtt_info->run_time && rtt_info->run_cpu != NO_CPU) {
		/* A box was started, finish it */
		info->box = TRUE;
		info->bcolor = hash_cpu(rtt_info->run_cpu);
		info->bfill = TRUE;
		info->bstart = rtt_info->run_time;
		info->bend = ginfo->view_end_time;
		info->blabel = rtt_info->label;
	} else if (rtt_info->block_time && rtt_info->block_cpu != NO_CPU) {
		/* Blocking happened */
		info->box = TRUE;
		info->bcolor = 0x0;
		info->bfill = TRUE;
		info->bthin = TRUE;
		info->bstart = rtt_info->block_time;
		info->bend = ginfo->view_end_time;
		rtt_info->fresh = FALSE;
	} else if (rtt_info->fresh) {
		/* Nothing happened!*/
		record = next_box_record(ginfo, rtt_info,
					   ginfo->view_end_time, &eid);

		if (record) {
			if (eid == rtg_info->switch_away_id) {
				/* In a run */
				info->box = TRUE;
				info->bcolor = hash_cpu(record->cpu);
				info->bfill = TRUE;
				info->bstart = ginfo->view_start_time;
				info->bend = ginfo->view_end_time;
			} else if (eid == rtg_info->task_resume_id) {
				/* In a block */
				info->box = TRUE;
				info->bcolor = 0x0;
				info->bfill = TRUE;
				info->bthin = TRUE;
				info->bstart = ginfo->view_start_time;
				info->bend = ginfo->view_end_time;
				rtt_info->fresh = FALSE;
			}
			free_record(record);
		}
	}
}

static int rt_task_plot_event(struct graph_info *ginfo, struct graph_plot *plot,
			      struct record *record, struct plot_info *info)
{
	struct rt_task_info *rtt_info = plot->private;
	int match;

	dprintf(4,"%s\n", __FUNCTION__);

	/* No more records, finish what we started */
	if (!record) {
		do_plot_end(ginfo, rtt_info, info);
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

	return match;
}

static void rt_task_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
			       unsigned long long time)
{
	int i;
	struct rt_task_info *rtt_info = plot->private;

	dprintf(4,"%s\n", __FUNCTION__);

	rtt_info->wcet = 0ULL;
	rtt_info->period = 0ULL;

	rtt_info->run_time = time;
	rtt_info->block_time = time;
	rtt_info->run_cpu = NO_CPU;
	rtt_info->block_cpu = NO_CPU;
	rtt_info->params_found = FALSE;
	rtt_info->fresh = TRUE;
	for (i = 0; i < 3; i++)
		rtt_info->first_rels[i] = 0ULL;
	rtt_info->last_job = 0;
}

static void rt_task_plot_destroy(struct graph_info *ginfo, struct graph_plot *plot)
{
	struct rt_task_info *rtt_info = plot->private;
	dprintf(4,"%s\n", __FUNCTION__);
	trace_graph_plot_remove_all_recs(ginfo, plot);
	free(rtt_info->label);
	free(rtt_info);
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

	dprintf(4,"%s\n", __FUNCTION__);

	offsets = save_offsets(ginfo);
	record = find_display_record(ginfo, rtt_info->pid, time);
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

static inline int in_res(struct graph_info *ginfo, unsigned long long time,
			 unsigned long target)
{
	return  time > target - 2/ginfo->resolution &&
		time < target + 2/ginfo->resolution;
}

static int rt_task_plot_display_info(struct graph_info *ginfo,
				     struct graph_plot *plot,
				     struct trace_seq *s,
				     unsigned long long time)
{
	const char *comm;
	int pid, job, eid;
	struct record *record;
	struct event_format *event;
	unsigned long long msec, nsec;
	unsigned long long release, deadline, rts;
	struct rt_task_info *rtt_info = plot->private;
	struct offset_cache *offsets;

	dprintf(4,"%s\n", __FUNCTION__);

	offsets = save_offsets(ginfo);
	get_time_info(ginfo, rtt_info, time,
		      &job, &release, &deadline, &record);
	restore_offsets(ginfo, offsets);

	pid = rtt_info->pid;
	comm = pevent_data_comm_from_pid(ginfo->pevent, pid);
	trace_seq_printf(s, "%s-%d:%d\n", comm, pid, job);

	if (record) {
		rts = get_rts(ginfo, record);
		eid = pevent_data_type(ginfo->pevent, record);

		if (in_res(ginfo, deadline, time)) {
			trace_seq_printf(s, "\nlitmus_deadline\n"
					 "deadline(job(%d,%d)): %llu\n",
					 pid, job, deadline);
		}
		if (in_res(ginfo, release, time)) {
			trace_seq_printf(s, "\nlitmus_release\n"
					 "release(job(%d,%d)): %llu\n",
					 pid, job, release);
		}

		if (in_res(ginfo, rts, time)) {
			event = pevent_data_event_from_type(ginfo->pevent, eid);
			if (event) {
				trace_seq_putc(s, '\n');
				trace_seq_puts(s, event->name);
				trace_seq_putc(s, '\n');
				pevent_event_info(s, event, record);
			} else
				trace_seq_printf(s, "\nUNKNOWN EVENT %d\n", eid);
		}
		trace_seq_putc(s, '\n');
		nano_to_milli(time, &msec, &nsec);
		trace_seq_printf(s, "%llu.%06llu ms CPU: %03d",
				 msec, nsec, record->cpu);
		free_record(record);
	}

	return 1;
}

static int rt_task_plot_match_time(struct graph_info *ginfo,
				   struct graph_plot *plot,
				   unsigned long long time)
{
	struct record *record = NULL;
	struct rt_task_info *rtt_info = plot->private;
	int next_cpu, match, ret;

	dprintf(4,"%s\n", __FUNCTION__);

	set_cpus_to_rts(ginfo, time);

	do {
		free_record(record);
		record = tracecmd_read_next_data(ginfo->handle, &next_cpu);
		if (!record)
			return 0;
		match = record_matches_pid(ginfo, record, rtt_info->pid);
	} while ((!match && get_rts(ginfo, record) < time + 1) ||
		 (match && get_rts(ginfo, record) < time));

	if (record && get_rts(ginfo, record) == time)
		ret = 1;
	free_record(record);

	return ret;
}

static struct record *
rt_task_plot_find_record(struct graph_info *ginfo, struct graph_plot *plot,
		      unsigned long long time)
{
	struct rt_task_info *rtt_info = plot->private;
	return find_record(ginfo, rtt_info->pid, time);
}


static const struct plot_callbacks rt_task_cb = {
	.start			= rt_task_plot_start,
	.destroy		= rt_task_plot_destroy,
	.plot_event		= rt_task_plot_event,
	.display_last_event	= rt_task_plot_display_last_event,
	.display_info		= rt_task_plot_display_info,
	.match_time		= rt_task_plot_match_time,
	.find_record		= rt_task_plot_find_record,
};

void rt_plot_task_update_callback(gboolean accept,
				  gint *selected,
				  gint *non_select,
				  gpointer data)
{
	struct graph_info *ginfo = data;
	struct rt_task_info *rtt_info;
	struct graph_plot *plot;
	gint select_size = 0;
	gint *ptr;
	int i;

	if (!accept)
		return;

	/* The selected and non_select are sorted */
	if (selected) {
		for (i = 0; selected[i] >= 0; i++)
			;
		select_size = i;
	}

	/*
	 * Remove and add task plots.
	 * Go backwards, since removing a plot shifts the
	 * array from current position back.
	 */
	for (i = ginfo->plots - 1; i >= 0; i--) {
		plot = ginfo->plot_array[i];
		if (plot->type != PLOT_TYPE_RT_TASK)
			continue;
		rtt_info = plot->private;

		/* If non are selected, then remove all */
		if (!select_size) {
			trace_graph_plot_remove(ginfo, plot);
			continue;
		}
		ptr = bsearch(&rtt_info->pid, selected, select_size,
			      sizeof(gint), id_cmp);
		if (ptr) {
			/*
			 * This plot plot already exists, remove it
			 * from the selected array.
			 */
			memmove(ptr, ptr + 1,
				(unsigned long)(selected + select_size) -
				(unsigned long)(ptr + 1));
			select_size--;
			continue;
		}
		/* Remove the plot */
		trace_graph_plot_remove(ginfo, plot);
	}

	/* Now add any plots that need to be added */
	for (i = 0; i < select_size; i++)
		rt_plot_task(ginfo, selected[i], ginfo->plots);

	trace_graph_refresh(ginfo);
}

void rt_plot_task_plotted(struct graph_info *ginfo, gint **plotted)
{
	struct task_plot_info *task_info;
	struct graph_plot *plot;
	int count = 0;
	int i;

	*plotted = NULL;
	for (i = 0; i < ginfo->plots; i++) {
		plot = ginfo->plot_array[i];
		if (plot->type != PLOT_TYPE_RT_TASK)
			continue;
		task_info = plot->private;
		trace_array_add(plotted, &count, task_info->pid);
	}
}

void rt_plot_task(struct graph_info *ginfo, int pid, int pos)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct rt_task_info *rtt_info;
	struct rt_task_params *params;
	struct graph_plot *plot;
	struct task_list *list;
	const char *comm;
	unsigned long long wm, wn, pm, pn;
	char *plot_label;
	int len;

	list = find_task_list(rtg_info->tasks, pid);
	if (!list)
		die("Cannot create RT plot of non-RT task %d!\n", pid);

	params = list->data;
	if (!params)
		die ("RT task %d added without RT params!\n", pid);
	rtt_info = malloc_or_die(sizeof(*rtt_info));
	rtt_info->pid = pid;
	rtt_info->label = malloc_or_die(LLABEL);

	nano_to_milli(params->wcet, &wm, &wn);
	nano_to_milli(params->period, &pm, &pn);

	/* Create plot */
	comm = pevent_data_comm_from_pid(ginfo->pevent, pid);
	len = strlen(comm) + 100;
	plot_label = malloc_or_die(len);
	snprintf(plot_label, len,
		 "%s-%d\n(%llu.%1llu, %llu.%1llu)",
		 comm, pid, wm, wn, pm, pn);
	plot = trace_graph_plot_insert(ginfo, pos, plot_label, PLOT_TYPE_RT_TASK,
				       TIME_TYPE_RT,
				       &rt_task_cb, rtt_info);
	free(plot_label);
	trace_graph_plot_add_all_recs(ginfo, plot);
}

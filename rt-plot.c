#include <gtk/gtk.h>
#include "trace-graph.h"

/**
 * Return first relevant record after @time.
 * @display: If set, only considers records which aren't plotted
 */
struct record*
__find_rt_record(struct graph_info *ginfo, struct rt_plot_common *rt_info,
		 guint64 time, int display)
{
	int next_cpu, match, eid, ignored;
	struct record *record;

	set_cpus_to_rts(ginfo, time);
	while ((record = tracecmd_read_next_data(ginfo->handle, &next_cpu))) {
		eid = pevent_data_type(ginfo->pevent, record);
		ignored = (eid == ginfo->event_sched_switch_id);
		if (!ignored && display) {
			ignored = rt_info->is_drawn(ginfo, eid);
		}
		match = !ignored &&
			rt_info->record_matches(rt_info, ginfo, record);

		if (get_rts(ginfo, record) >= time && match)
			break;
		free_record(record);
	};

	return record;
}

/**
 * rt_plot_display_last_event - write event name at @time onto plot.
 */
int
rt_plot_display_last_event(struct graph_info *ginfo, struct graph_plot *plot,
			   struct trace_seq *s, unsigned long long time)
{
	int eid;
	struct event_format *event;
	struct record *record;
	struct offset_cache *offsets;
	struct rt_plot_common *rt_info = plot->private;

	offsets = save_offsets(ginfo);

	record = find_rt_display_record(ginfo, rt_info, time);

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

static struct record*
find_prev_record(struct graph_info *ginfo, struct rt_plot_common *rt_info,
		 unsigned long long time)
{
	int eid, ignored, match, cpu;
	struct record *prev, *res = NULL;
	unsigned long long min_ts;

	min_ts = time - max_rt_search(ginfo);

	set_cpus_to_rts(ginfo, time);

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		prev = tracecmd_peek_data(ginfo->handle, cpu);
		while ((prev = tracecmd_read_prev(ginfo->handle, prev)) &&
		       get_rts(ginfo, prev) > min_ts) {
			eid = pevent_data_type(ginfo->pevent, prev);
			ignored = (eid == ginfo->event_sched_switch_id);
			if (!ignored) {
				ignored = rt_info->is_drawn(ginfo, eid);
			}
			match = !ignored &&
				rt_info->record_matches(rt_info, ginfo, prev);
			if (match) {
				if (!res ||
				    get_rts(ginfo, prev) > get_rts(ginfo, res)) {
					free_record(res);
					res = prev;
				}
				break;
			}
			free_record(prev);
		}
	}
	return res;
}

/**
 * rt_plot_display_info - write information about @time into @s
 */
int
rt_plot_display_info(struct graph_info *ginfo, struct graph_plot *plot,
		     struct trace_seq *s, unsigned long long time)
{
	struct rt_plot_common *rt_info = plot->private;
	struct event_format *event;
	struct record *record, *prev_record;
	unsigned long long msec, nsec, rts;
	int eid;

	record = rt_info->write_header(rt_info, ginfo, s, time);
	prev_record = find_prev_record(ginfo, rt_info, time);

	if (!record || (prev_record && prev_record != record &&
			(time - get_rts(ginfo, prev_record)) <
			(get_rts(ginfo, record) - time))) {
			free_record(record);
			record = prev_record;
	}

	if (record) {
		rts = get_rts(ginfo, record);
		eid = pevent_data_type(ginfo->pevent, record);

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

/**
 * rt_plot_find_rt_record - return matching record around @time.
 */
 struct record*
rt_plot_find_record(struct graph_info *ginfo, struct graph_plot *plot,
		    unsigned long long time)
{
	return find_rt_record(ginfo, plot->private, time);
}

/**
 * rt_plot_match_time - return 1 if there is an exact match at @time.
 */
int
rt_plot_match_time(struct graph_info *ginfo, struct graph_plot *plot,
		   unsigned long long time)
{
	struct record *record = NULL;
	struct rt_plot_common *rt_info = plot->private;
	int next_cpu, match, ret;

	set_cpus_to_rts(ginfo, time);

	do {
		free_record(record);
		record = tracecmd_read_next_data(ginfo->handle, &next_cpu);
		if (!record)
			return 0;
		match = rt_info->record_matches(rt_info, ginfo, record);
	} while ((!match && get_rts(ginfo, record) < time + 1) ||
		 (match && get_rts(ginfo, record) < time));

	if (record && get_rts(ginfo, record) == time)
		ret = 1;
	free_record(record);

	return ret;
}



/**
 * next_rts - find a real-time timestamp AROUND an FTRACE time
 * @ginfo: Current state of the graph
 * @cpu: CPU to search
 * @ft_target: FTRACE time to seek towards
 *
 * Returns the RT time of a record CLOSELY BEFORE @ft_time.
 */
unsigned long long
next_rts(struct graph_info *ginfo, int cpu, unsigned long long ft_target)
{
	struct record *record;
	unsigned long long ts = 0ULL;
	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, ft_target);
	record = tracecmd_read_data(ginfo->handle, cpu);
	if (record) {
		ts = get_rts(ginfo, record);
		free_record(record);
		return ts;
	} else
		return 0;
}

/**
 * set_cpu_to_rts - seek CPU to a time closely preceding a real-time timestamp
 * @ginfo: Current state o the graph
 * @cpu: The CPU to seek
 * @rt_target: RT time to seek towards
 *
 * This seeks to a real-time timestamp, not the default ftrace timestamps.
 * The @cpu seek location will be placed before the given time, but will
 * not necessarily be placed _right_ before the time.
 */
void
set_cpu_to_rts(struct graph_info *ginfo, unsigned long long rt_target, int cpu)
{
	struct record *record;
	unsigned long long last_rts, rts, seek_time, last_seek;
	long long diff;

	rts = next_rts(ginfo, cpu, rt_target);
	diff = rt_target - rts;

	/* "Guess" a new target based on difference */
	seek_time = rt_target + diff;
	rts = next_rts(ginfo, cpu, seek_time);
	diff = rt_target - rts;

	/* Zero in in 1.5x the difference increments */
	if (rts && diff > 0) {
		/*   rts      rt_target  | real-time time
		 *   seek        ?       | trace-cmd time
		 * ---|---->>----|--------
		 */
		do {
			last_seek = seek_time;
			last_rts = rts;
			seek_time = seek_time + 1.5 * (rt_target - rts);
			rts = next_rts(ginfo, cpu, seek_time);
		} while (rts < rt_target && last_rts != rts);
		tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, last_seek);
		seek_time = last_seek;
	} else if (rts && diff < 0) {
		/* rt_target    rts      | real-time time
		 *    ?         seek     | trace-cmd time
		 * ---|----<<----|--------
		 */
		do {
			seek_time = seek_time - 1.5 * (rts - rt_target);
			rts = next_rts(ginfo, cpu, seek_time);
		} while (rts > rt_target);
	}

	/* Get to first record at or after time */
	while ((record = tracecmd_read_data(ginfo->handle, cpu))) {
		if (get_rts(ginfo, record) >= rt_target)
			break;
		free_record(record);
	}
	if (record) {
		tracecmd_set_cursor(ginfo->handle, cpu, record->offset);
		free_record(record);
	} else
		tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, seek_time);
}

/**
 * set_cpus_to_time - seek all cpus to real-time @rt_target
 */
void set_cpus_to_rts(struct graph_info *ginfo, unsigned long long rt_target)
{
	int cpu;
	for (cpu = 0; cpu < ginfo->cpus; cpu++)
		set_cpu_to_rts(ginfo, rt_target, cpu);
}


/**
 * is_task_running - return 1 if @match_pid is running at @time.
 */
int is_task_running(struct graph_info *ginfo,
		    unsigned long long time,
		    int match_pid)
{
	int pid, job, cpu, running = 0;
	unsigned long long ts, min_ts;
	struct record *rec;

	set_cpus_to_rts(ginfo, time);

	min_ts = time - max_rt_search(ginfo);

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		rec = tracecmd_peek_data(ginfo->handle, cpu);
		if (!rec)
			continue;

		while ((rec = tracecmd_read_prev(ginfo->handle, rec))) {
			if (get_rts(ginfo, rec) < min_ts)
				goto out;

#define ARG ginfo, rec, &pid, &job, &ts
			if (rt_graph_check_switch_away(ARG)) {
				if (pid == match_pid)
					goto out;
			} else if (rt_graph_check_switch_to(ARG)) {
				if (pid == match_pid) {
					running = 1;
					goto out;
				}
			}
#undef ARG
		}
		free_record(rec);

	}
 out:
	free_record(rec);
	return running;
}

/**
 * Find the information for the last release of @match_tid on @cpu before @time.
 *
 * This method will NOT re-seek the CPUs near time. The caller must have placed
 * the CPUs near the the CPUs themselves.
 *
 * Returns release record and @out_job, @out_release, and @out_deadline if a
 * release was found for @tid before @time.
 */
struct record* get_previous_release(struct graph_info *ginfo, int match_tid,
				    unsigned long long time,
				    int *out_job,
				    unsigned long long *out_release,
				    unsigned long long *out_deadline)
{
	int tid, cpu, match, job;
	unsigned long long release, deadline, min_ts;
	struct record *last_rec = NULL, *rec, *ret = NULL;

	min_ts = time - max_rt_search(ginfo);

	/* The release record could have occurred on any CPU. Search all */
	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		last_rec = tracecmd_peek_data(ginfo->handle, cpu);

		/* Require a record to start with */
		if (!last_rec)
			goto loop_end;
		last_rec->ref_count++;

		while ((rec = tracecmd_read_prev(ginfo->handle, last_rec))) {
			if (rec->ts < min_ts) {
				free_record(rec);
				goto loop_end;
			}

#define ARG ginfo, rec, &tid, &job, &release, &deadline
			match = rt_graph_check_task_release(ARG) ||
				rt_graph_check_server_release(ARG);
#undef ARG

			free_record(last_rec);
			last_rec = rec;

			/* Only consider releases before the current time */
			if (match && tid == match_tid && release <= time) {
				/* Return the lastest release */
				if (!ret || *out_job < job) {
					free_record(ret);
					ret = rec;
					*out_job = job;
					*out_release = release;
					*out_deadline = deadline;
				}

				last_rec = NULL;
				goto loop_end;
			}
		}
	loop_end:
		free_record(last_rec);
	}
	return ret;
}

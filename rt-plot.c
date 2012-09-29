#include <gtk/gtk.h>
#include <string.h>
#include "trace-graph.h"
#include "list.h"


struct record_list {
	struct record_list *next;
	struct record *record;
};

/*
 * Insert @record into @list, storing the record in @node.
 */
void insert_record(struct graph_info *ginfo, struct record_list *list,
		   struct record *record, struct record_list *node,
		   int reverse)
{
	if (node->next)
		die("Node is in use!");
	if (!record) {
		return;
	}

	node->record = record;

	struct record_list *pos = list;

	while (pos->next) {
		unsigned long long next_rts = get_rts(ginfo, pos->next->record);
		if (( reverse && !next_rts > get_rts(ginfo, record)) ||
		    (!reverse &&  next_rts < get_rts(ginfo, record))){
			break;
		}
		pos = pos->next;
	}

	node->next = pos->next;
	pos->next = node;	
}


/*
 * Remove the first record in @list and put into @node.
 */
int pop_record(struct graph_info *ginfo, struct record_list *list,
	       struct record_list **node)
{
	if (!list->next)
		return 0;

	*node = list->next;
	list->next = list->next->next;
	(*node)->next = 0;

	return 1;	
}


/* For communication between get_previous_release and its iterator */
struct prev_release_args {
	unsigned long long min_ts;
	struct rt_plot_common *common;
	unsigned long long time;
	int match_tid;
	unsigned int *out_job;
	unsigned long long *out_release;
	unsigned long long *out_deadline;
};


static int
prev_release_iterator(struct graph_info *ginfo, struct record *rec, void *data)
{
	int tid, is_release, job;
	unsigned long long release, deadline;
	struct prev_release_args *args = data;

	if (get_rts(ginfo, rec) < args->min_ts) {
		args->common->last_job.release = get_rts(ginfo, rec);
		args->common->last_job.deadline = args->time;
		return 0;
	}

#define ARG ginfo, rec, &tid, &job, &release, &deadline
	is_release = rt_graph_check_task_release(ARG) ||
		     rt_graph_check_server_release(ARG);
#undef ARG

	if (is_release && args->match_tid == tid && release <= args->time) {
		*(args->out_job) = job;
		*(args->out_release) = release;
		*(args->out_deadline) = deadline;
		
		/* Cache to minimize work later */
		args->common->last_job.no = job;
		args->common->last_job.release = release;
		args->common->last_job.deadline = deadline;
		args->common->last_job.start = get_rts(ginfo, rec);
		args->common->last_job.end = args->time;
		return 0;
	} else {
		return 1;
	}
}


/* For communication between find_prev_display_record and its iterator */
struct prev_display_args {
	struct rt_plot_common *common;
	struct record *result;
	unsigned long long min_ts;
};


static int
prev_display_iterator(struct graph_info *ginfo, struct record *record, void *data)
{
	int eid, ignored;
	struct prev_display_args *args = data;

	if (get_rts(ginfo, record) < args->min_ts) {
		return 0;
	}
		
	eid = pevent_data_type(ginfo->pevent, record);
	ignored = (eid == ginfo->event_sched_switch_id);

	if (!ignored) {
		ignored = args->common->is_drawn(ginfo, eid);
	}
	
	if (!ignored && args->common->record_matches(args->common, ginfo, record)) {
		args->result = record;
		++record->ref_count;
		return 0;
	} else {
		return 1;
	}
}


/*
 * Return first displayed record before @time, abandoning search after @range.
 */
static struct record*
find_prev_display_record(struct graph_info *ginfo, struct rt_plot_common *rt_info,
		 unsigned long long time, unsigned long long range)
{
	int eid, ignored, match, cpu;
	struct record *prev, *next, *res = NULL;
	struct prev_display_args args = {rt_info, NULL, 0};

	if (range) {
		args.min_ts = time - range;
	} else {
		args.min_ts = time - max_rt_search(ginfo);
	}

	set_cpus_to_rts(ginfo, time);
	iterate(ginfo, 1, prev_display_iterator, &args);

	return args.result;
}


/**
 * Return first relevant record after @time.
 * @display: If set, only considers records which aren't plotted
 */
struct record*
__find_rt_record(struct graph_info *ginfo, struct rt_plot_common *rt_info,
		 guint64 time, int display, unsigned long long range)
{
	int next_cpu, match, eid, ignored;
	struct record *record = NULL;

	set_cpus_to_rts(ginfo, time);
	while ((record = tracecmd_read_next_data(ginfo->handle, &next_cpu))) {

		if (range && get_rts(ginfo, record) >= time + range) {
			free_record(record);
			record = NULL;
			break;
		}

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

/**
 * rt_plot_display_info - write information about @time into @s
 */
int
rt_plot_display_info(struct graph_info *ginfo, struct graph_plot *plot,
		     struct trace_seq *s, unsigned long long time)
{
	struct rt_plot_common *rt_info = plot->private;
	struct event_format *event;
	struct record *record = NULL, *prev_record = NULL, *data_record = NULL;
	unsigned long long msec, nsec, rts, ptime, rtime, range;
	long long pdiff, rdiff;
	int eid;

	/* Write plot-specific data */
	data_record = rt_info->write_header(rt_info, ginfo, s, time);

	/* Select closest relevant record */
	range = 2 / ginfo->resolution;

	record = __find_rt_record(ginfo, rt_info, time, 1, range);
	prev_record = find_prev_display_record(ginfo, rt_info, time, range);

	if (!record) {
		record = prev_record;
	} else if (prev_record) {
		ptime = get_rts(ginfo, prev_record);
		rtime = get_rts(ginfo, record);
		pdiff = (ptime < time) ? time - ptime : ptime - time;
		rdiff = (rtime < time) ? time - rtime : rtime - time;
		if (pdiff < rdiff) {
			free_record(record);
			record = prev_record;
		} else {
			free_record(prev_record);
		}
	}

	/* Write event info */
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
		free_record(record);
	}

	/* Metadata */
	trace_seq_putc(s, '\n');
	nano_to_milli(time, &msec, &nsec);
	trace_seq_printf(s, "%llu.%06llu ms", msec, nsec);

	if (data_record) {
		trace_seq_printf(s, " CPU: %03d", data_record->cpu);
		free_record(data_record);
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
unsigned long long
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
			last_rts = rts;
			rts = next_rts(ginfo, cpu, seek_time);
		} while (rts > rt_target && rts != last_rts);
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
	return rts;
}

/**
 * set_cpus_to_time - seek all cpus to real-time @rt_target
 */
unsigned long long set_cpus_to_rts(struct graph_info *ginfo, unsigned long long rt_target)
{
	int cpu;
	unsigned long long min_rts = ULLONG_MAX;
	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		unsigned long long rts = set_cpu_to_rts(ginfo, rt_target, cpu);
		min_rts = MIN(min_rts, rts);
	}
	return min_rts;
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

void iterate(struct graph_info *ginfo, int reverse, iterate_cb cb, void *data)
{
	int proceed, cpu;
	struct record *next, *prev;
	struct record_list list;
	struct record_list *nodes, *node;

	nodes = malloc_or_die(sizeof(*nodes) * ginfo->cpus);
	memset(nodes, 0, sizeof(*nodes) * ginfo->cpus);
	memset(&list, 0, sizeof(list));

	/* Maintains a list of the next record on each cpu, sorted by
	 * timestamp. Start with the first record on each cpu.
	 */
	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		next = tracecmd_peek_data(ginfo->handle, cpu);
		if (next) {
			if (reverse) {
				prev = next;
				next = tracecmd_read_prev(ginfo->handle, prev);
				if (prev != next && prev->data) {
					free_record(prev);
				}
			}
			insert_record(ginfo, &list, next, &nodes[cpu], reverse);
		}
	}

	/* Read sequentially from all cpus */
	while (pop_record(ginfo, &list, &node)) {
		next = node->record;

		proceed = cb(ginfo, next, data);

		if (!proceed) {
			free_record(next);
			break;
		} 

		prev = next;

		if (!reverse) {
			next = tracecmd_read_data(ginfo->handle, next->cpu);
		} else {
			next = tracecmd_read_prev(ginfo->handle, next);
		}

		free_record(prev);

		insert_record(ginfo, &list, next, node, reverse);
	}

	while (pop_record(ginfo, &list, &node)) {
		free_record(node->record);
	}
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
void get_previous_release(struct graph_info *ginfo, struct rt_plot_common *common,
			  int match_tid,
			  unsigned long long time,
			  int *out_job,
			  unsigned long long *out_release,
			  unsigned long long *out_deadline)
{
	struct prev_release_args args = {
		(time - max_rt_search(ginfo)), common, time, match_tid,
		out_job, out_release, out_deadline};

	/* Use cached job info, if possible */
	if (time >= common->last_job.start &&
	    time <= common->last_job.end) {
		*out_job = common->last_job.no;
		*out_release = common->last_job.release;
		*out_deadline = common->last_job.deadline;
		return;
	}

	set_cpus_to_rts(ginfo, time);
	iterate(ginfo, 1, prev_release_iterator, &args);
}

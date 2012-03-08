#include "trace-graph.h"
#include "trace-hash.h"

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

static guint get_event_hash_key(gint eid)
{
	return trace_hash(eid) % TS_HASH_SIZE;
}

/*
 * Returns cached field for @eid at @key.
 */
struct format_field* find_ts_hash(struct ts_list **events,
				  gint key, gint eid)
{
	struct ts_list *list;
	for (list = events[key]; list; list = list->next) {
		if (list->eid == eid)
			return list->ts_field;
	}
	return NULL;
}

/*
 * Return field for @eid at @key, caching if necessary.
 */
static struct format_field*
add_ts_hash(struct ts_list **events, gint eid, gint key,
	    struct pevent *pevent, struct record *record)
{
	struct ts_list *list;
	struct format_field *field;
	struct event_format *event;

	event = pevent_find_event(pevent, eid);
	if (!event)
		die("Could not find event %d for record!\n", eid);
	field = pevent_find_field(event, RT_TS_FIELD);

	list = malloc_or_die(sizeof(*list));
	list->eid = eid;
	list->next = events[key];
	list->ts_field = field;
	events[key] = list;

	return field;
}

/**
 * rt_graph_check_any - parse timestamp of any record
 * @epid: set to the event's task PID
 * @rt_ts: set to the event's real-time timestamp
 */
int rt_graph_check_any(struct rt_graph_info *rtinfo,
		       struct pevent *pevent, struct record *record,
		       gint *epid, gint *out_eid, unsigned long long *ts)
{
	guint key, eid;
	struct format_field *field;

	eid = pevent_data_type(pevent, record);
	key = get_event_hash_key(eid);
	field = find_ts_hash(rtinfo->events, key, eid);

	if (!field)
		field = add_ts_hash(rtinfo->events, eid, key, pevent, record);

	*epid = pevent_data_pid(pevent, record);
	pevent_read_number_field(field, record->data, ts);

	dprintf(3, "Read (%d) record for task %d at %llu\n",
		eid, *epid, *ts);
	*out_eid = eid;
	return 1;
}

/**
 * rt_graph_check_task_param - check for litmus_task_param record
 * Return 1 and @pid, @wcet, and @period if the record matches
 */
int rt_graph_check_task_param(struct rt_graph_info *rtinfo,
			      struct pevent *pevent, struct record *record,
			      gint *pid, unsigned long long *wcet,
			      unsigned long long *period)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	/* Attempt to update record cache. It can only be updated
	 * after the pevent has "seen" its first litmus_task_param
	 * event.
	 */
	if (rtinfo->task_param_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_param");
		if (!event)
			goto out;
		rtinfo->task_param_id = event->id;
		dprintf(2, "Found task_param id %d\n", event->id);
		rtinfo->param_pid_field = pevent_find_field(event, "pid");
		rtinfo->param_wcet_field = pevent_find_field(event, "wcet");
		rtinfo->param_period_field = pevent_find_field(event, "period");
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_param_id) {
		pevent_read_number_field(rtinfo->param_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->param_wcet_field,
					 record->data, wcet);
		pevent_read_number_field(rtinfo->param_period_field,
					 record->data, period);
		ret = 1;
		dprintf(3, "Read task_param (%d) record for task %d "
			"(%llu, %llu)\n", id, *pid, *wcet, *period);

		add_task_hash(rtinfo->tasks, *pid);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_switch_to - check for litmus_switch_to record
 * Return 1 and @pid, @job, and @ts if the record matches
 */
int rt_graph_check_switch_to(struct rt_graph_info *rtinfo,
				  struct pevent *pevent, struct record *record,
				  gint *pid, gint *job,
				  unsigned long long *ts)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->switch_to_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_switch_to");
		if (!event)
			goto out;
		rtinfo->switch_to_id = event->id;
		dprintf(2, "Found switch_to id %d\n", event->id);
		rtinfo->switch_to_pid_field = pevent_find_field(event, "pid");
		rtinfo->switch_to_job_field = pevent_find_field(event, "job");
		rtinfo->switch_to_ts_field = pevent_find_field(event, RT_TS_FIELD);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->switch_to_id) {
		pevent_read_number_field(rtinfo->switch_to_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->switch_to_job_field,
					 record->data, &val);
		*job = val;
		pevent_read_number_field(rtinfo->switch_to_ts_field,
					 record->data, ts);
		ret = 1;
		dprintf(3, "Read switch_to (%d) record for job %d:%d, "
			"ts: %llu\n", id, *pid, *job, *ts);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_switch_away - check for litmus_switch_away record
 * Return 1 and @pid, @job, and @ts if the record matches
 */
int rt_graph_check_switch_away(struct rt_graph_info *rtinfo,
				    struct pevent *pevent, struct record *record,
				    gint *pid, gint *job,
				    unsigned long long *ts)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->switch_away_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_switch_away");
		if (!event)
			goto out;
		rtinfo->switch_away_id = event->id;
		dprintf(2, "Found switch_away id %d\n", event->id);
		rtinfo->switch_away_pid_field = pevent_find_field(event, "pid");
		rtinfo->switch_away_job_field = pevent_find_field(event, "job");
		rtinfo->switch_away_ts_field = pevent_find_field(event, RT_TS_FIELD);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->switch_away_id) {
		pevent_read_number_field(rtinfo->switch_away_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->switch_away_job_field,
					 record->data, &val);
		*job = val;
		pevent_read_number_field(rtinfo->switch_away_ts_field,
					 record->data, ts);
		ret = 1;
		dprintf(3, "Read switch_away (%d) record for job %d:%d, "
			"ts: %llu\n", id, *pid, *job, *ts);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_release - check for litmus_task_release record
 * Return 1 and @pid, @job, @release, and @deadline if the record matches
 */
int rt_graph_check_task_release(struct rt_graph_info *rtinfo,
				struct pevent *pevent, struct record *record,
				gint *pid, gint *job,
				unsigned long long *release,
				unsigned long long *deadline)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->task_release_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_release");
		if (!event)
			goto out;
		rtinfo->task_release_id = event->id;
		dprintf(2, "Found task_release id %d\n", event->id);
		rtinfo->release_pid_field = pevent_find_field(event, "pid");
		rtinfo->release_job_field = pevent_find_field(event, "job");
		rtinfo->release_release_field = pevent_find_field(event, "release");
		rtinfo->release_deadline_field = pevent_find_field(event, "deadline");
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_release_id) {
		pevent_read_number_field(rtinfo->release_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->release_job_field,
					 record->data, &val);
		*job = val;
		pevent_read_number_field(rtinfo->release_release_field,
					 record->data, release);
		pevent_read_number_field(rtinfo->release_deadline_field,
					 record->data, deadline);
		ret = 1;
		dprintf(3, "Read task_release (%d) record for job %d:%d, "
			"release: %llu, dead: %llu\n", id, *pid, *job, *release,
			*deadline);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_completion - check for litmus_task_completion record
 * Return 1 and @pid, @job, and @ts if the record matches
 */
int rt_graph_check_task_completion(struct rt_graph_info *rtinfo,
				   struct pevent *pevent, struct record *record,
				   gint *pid, gint *job, unsigned long long *ts)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->task_completion_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_completion");
		if (!event)
			goto out;
		rtinfo->task_completion_id = event->id;
		dprintf(2, "Found task_completion id %d\n", event->id);
		rtinfo->completion_pid_field = pevent_find_field(event, "pid");
		rtinfo->completion_job_field = pevent_find_field(event, "job");
		rtinfo->completion_ts_field = pevent_find_field(event, RT_TS_FIELD);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_completion_id) {
		pevent_read_number_field(rtinfo->completion_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->completion_job_field,
					 record->data, &val);
		*job = val;
		pevent_read_number_field(rtinfo->completion_ts_field,
					 record->data, ts);
		ret = 1;
		dprintf(3, "Read task_completion (%d) record for job %d:%d "
			"ts: %llu\n", id, *pid, *job, *ts);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_block - check for litmus_task_block record
 * Return 1, @pid, and @ts if the record matches
 */
int rt_graph_check_task_block(struct rt_graph_info *rtinfo,
			      struct pevent *pevent, struct record *record,
			      gint *pid, unsigned long long *ts)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->task_block_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_block");
		if (!event)
			goto out;
		dprintf(2, "Found task_block id %d\n", event->id);
		rtinfo->task_block_id = event->id;
		rtinfo->block_pid_field = pevent_find_field(event, "pid");
		rtinfo->block_ts_field = pevent_find_field(event, RT_TS_FIELD);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_block_id) {
		pevent_read_number_field(rtinfo->block_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->block_ts_field,
					 record->data, ts);
		ret = 1;
		dprintf(3, "Read task_block (%d) record for task %d\n",
			id, *pid);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_resume - check for litmus_task_resume record
 * Return 1 and @pid if the record matches
 */
int rt_graph_check_task_resume(struct rt_graph_info *rtinfo,
			       struct pevent *pevent, struct record *record,
			       gint *pid, unsigned long long *ts)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->task_resume_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_resume");
		if (!event)
			goto out;
		dprintf(2, "Found task_resume id %d\n", event->id);
		rtinfo->task_resume_id = event->id;
		rtinfo->resume_pid_field = pevent_find_field(event, "pid");
		rtinfo->resume_ts_field = pevent_find_field(event, RT_TS_FIELD);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_resume_id) {
		pevent_read_number_field(rtinfo->resume_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->resume_ts_field,
					 record->data, ts);
		ret = 1;
		dprintf(3, "Read task_resume (%d) record for task %d\n",
			id, *pid);
	}
 out:
	return ret;
}

/**
 * init_rt_event_cache - reset cached field values
 */
void init_rt_event_cache(struct rt_graph_info *rtinfo)
{
	dprintf(1, "Initializing RT event cache\n");
	rtinfo->task_param_id = -1;
	rtinfo->switch_to_id = -1;
	rtinfo->switch_away_id = -1;
	rtinfo->task_release_id = -1;
	rtinfo->task_completion_id = -1;
	rtinfo->task_block_id = -1;
	rtinfo->task_resume_id = -1;

	rtinfo->param_pid_field = NULL;
	rtinfo->param_wcet_field = NULL;
	rtinfo->param_period_field = NULL;

	rtinfo->switch_to_pid_field = NULL;
	rtinfo->switch_to_job_field = NULL;
	rtinfo->switch_to_ts_field = NULL;

	rtinfo->switch_away_pid_field = NULL;
	rtinfo->switch_away_job_field = NULL;
	rtinfo->switch_away_ts_field = NULL;

	rtinfo->release_pid_field = NULL;
	rtinfo->release_job_field = NULL;
	rtinfo->release_release_field = NULL;
	rtinfo->release_deadline_field = NULL;

	rtinfo->completion_pid_field = NULL;
	rtinfo->completion_job_field = NULL;
	rtinfo->completion_ts_field = NULL;

	rtinfo->block_pid_field = NULL;
	rtinfo->block_ts_field = NULL;

	rtinfo->resume_pid_field = NULL;
	rtinfo->resume_ts_field = NULL;
}

/**
 * get_rts - extract real-time timestamp from a record
 *
 * This will only have to extract the timestamp once; after the time
 * is extracted it will be cached in the record itself.
 */
unsigned long long
get_rts(struct graph_info *ginfo, struct record *record)
{
	gint epid, eid;
	unsigned long long ts;
	if (!record->cached_rts) {
		rt_graph_check_any(&ginfo->rtinfo, ginfo->pevent, record,
				   &epid, &eid, &ts);
		record->cached_rts = ts;
	} else
		ts = record->cached_rts;
	return ts;
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
		/*   rts      rt_target
		 *   seek        ?
		 * ---|---->>----|---
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
		/* rt_target    rts
		 *    ?         seek
		 * ---|----<<----|---
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

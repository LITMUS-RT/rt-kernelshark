#include "rt-graph.h"
#include "trace-hash.h"

#define DEBUG_LEVEL	1
#if DEBUG_LEVEL > 0
#define dprintf(l, x...)			\
	do {					\
		if (l <= DEBUG_LEVEL)		\
			printf(x);		\
	} while (0)
#else
#define dprintf(l, x...)	do { if (0) printf(x); } while (0)
#endif

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

		/* Only of these per task, so we can safely add new tasks now */
		add_task_hash(rtinfo->tasks, *pid);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_switch_to - check for litmus_task_switch_to record
 * Return 1 and @pid, @job, and @when if the record matches
 */
int rt_graph_check_task_switch_to(struct rt_graph_info *rtinfo,
				  struct pevent *pevent, struct record *record,
				  gint *pid, gint *job,
				  unsigned long long *when)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->task_switch_to_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_switch_to");
		if (!event)
			goto out;
		rtinfo->task_switch_to_id = event->id;
		dprintf(2, "Found task_switch_to id %d\n", event->id);
		rtinfo->switch_to_pid_field = pevent_find_field(event, "pid");
		rtinfo->switch_to_job_field = pevent_find_field(event, "job");
		rtinfo->switch_to_when_field = pevent_find_field(event, "when");
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_switch_to_id) {
		pevent_read_number_field(rtinfo->switch_to_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->switch_to_job_field,
					 record->data, &val);
		*job = val;
		pevent_read_number_field(rtinfo->switch_to_when_field,
					 record->data, when);
		ret = 1;
		dprintf(3, "Read task_switch_to (%d) record for job %d:%d, "
			"when: %llu\n", id, *pid, *job, *when);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_switch_away - check for litmus_task_switch_away record
 * Return 1 and @pid, @job, and @when if the record matches
 */
int rt_graph_check_task_switch_away(struct rt_graph_info *rtinfo,
				    struct pevent *pevent, struct record *record,
				    gint *pid, gint *job,
				    unsigned long long *when)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->task_switch_away_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_switch_away");
		if (!event)
			goto out;
		rtinfo->task_switch_away_id = event->id;
		dprintf(2, "Found task_switch_away id %d\n", event->id);
		rtinfo->switch_away_pid_field = pevent_find_field(event, "pid");
		rtinfo->switch_away_job_field = pevent_find_field(event, "job");
		rtinfo->switch_away_when_field = pevent_find_field(event, "when");
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_switch_away_id) {
		pevent_read_number_field(rtinfo->switch_away_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->switch_away_job_field,
					 record->data, &val);
		*job = val;
		pevent_read_number_field(rtinfo->switch_away_when_field,
					 record->data, when);
		ret = 1;
		dprintf(3, "Read task_switch_away (%d) record for job %d:%d, "
			"when: %llu\n", id, *pid, *job, *when);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_release - check for litmus_task_release record
 * Return 1 and @pid, @job, and @deadline if the record matches
 */
int rt_graph_check_task_release(struct rt_graph_info *rtinfo,
				struct pevent *pevent, struct record *record,
				gint *pid, gint *job, unsigned long long *release,
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
			"dead: %llu\n", id, *pid, *job, *deadline);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_completion - check for litmus_task_completion record
 * Return 1 and @pid, @job if the record matches
 */
int rt_graph_check_task_completion(struct rt_graph_info *rtinfo,
				   struct pevent *pevent, struct record *record,
				   gint *pid, gint *job, unsigned long long *when)
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
		rtinfo->completion_when_field = pevent_find_field(event, "when");
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_completion_id) {
		pevent_read_number_field(rtinfo->completion_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->completion_job_field,
					 record->data, &val);
		*job = val;
		pevent_read_number_field(rtinfo->completion_when_field,
					 record->data, when);
		ret = 1;
		dprintf(3, "Read task_completion (%d) record for job %d:%d\n",
			id, *pid, *job);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_block - check for litmus_task_block record
 * Return 1 and @pid if the record matches
 */
int rt_graph_check_task_block(struct rt_graph_info *rtinfo,
			      struct pevent *pevent, struct record *record,
			      gint *pid, unsigned long long *when)
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
		rtinfo->block_when_field = pevent_find_field(event, "when");
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_block_id) {
		pevent_read_number_field(rtinfo->block_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->block_when_field,
					 record->data, when);
		ret = 1;
		dprintf(3, "Read task_block (%d) record for task %d\n",
			id, *pid);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_release - check for litmus_task_release record
 * Return 1 and @pid if the record matches
 */
int rt_graph_check_task_resume(struct rt_graph_info *rtinfo,
			       struct pevent *pevent, struct record *record,
			       gint *pid, unsigned long long *when)
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
		rtinfo->resume_when_field = pevent_find_field(event, "when");
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_resume_id) {
		pevent_read_number_field(rtinfo->resume_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->resume_when_field,
					 record->data, when);
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
	rtinfo->task_switch_to_id = -1;
	rtinfo->task_switch_away = -1;
	rtinfo->task_release_id = -1;
	rtinfo->task_completion_id = -1;
	rtinfo->task_block_id = -1;
	rtinfo->task_resume_id = -1;

	rtinfo->param_pid_field = NULL;
	rtinfo->param_wcet_field = NULL;
	rtinfo->param_period_field = NULL;

	rtinfo->switch_to_pid_field = NULL;
	rtinfo->switch_to_job_field = NULL;
	rtinfo->switch_to_when_field = NULL;

	rtinfo->switch_away_pid_field = NULL;
	rtinfo->switch_away_job_field = NULL;
	rtinfo->switch_away_when_field = NULL;

	rtinfo->release_pid_field = NULL;
	rtinfo->release_job_field = NULL;
	rtinfo->release_release_field = NULL;
	rtinfo->release_deadline_field = NULL;

	rtinfo->completion_pid_field = NULL;
	rtinfo->completion_job_field = NULL;
	rtinfo->completion_when_field = NULL;

	rtinfo->block_pid_field = NULL;
	rtinfo->block_when_field = NULL;

	rtinfo->resume_pid_field = NULL;
	rtinfo->resume_when_field = NULL;
}

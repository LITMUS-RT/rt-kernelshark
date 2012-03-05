#include "rt-graph.h"

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
			return 0;
		rtinfo->task_param_id = event->id;
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
	}

	return ret;
}

/**
 * rt_graph_check_task_release - check for litmus_task_release record
 * Return 1 and @pid, @job, and @deadline if the record matches
 */
int rt_graph_check_task_release(struct rt_graph_info *rtinfo,
				struct pevent *pevent, struct record *record,
				gint *pid, gint *job,
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
			return 0;
		rtinfo->task_release_id = event->id;
		rtinfo->release_pid_field = pevent_find_field(event, "pid");
		rtinfo->release_job_field = pevent_find_field(event, "job");
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
		pevent_read_number_field(rtinfo->release_deadline_field,
					 record->data, deadline);
		ret = 1;
	}

	return ret;
}

/**
 * rt_graph_check_task_completion - check for litmus_task_completion record
 * Return 1 and @pid, @job if the record matches
 */
int rt_graph_check_task_completion(struct rt_graph_info *rtinfo,
				   struct pevent *pevent, struct record *record,
				   gint *pid, gint *job)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->task_param_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_completion");
		if (!event)
			return 0;
		rtinfo->task_completion_id = event->id;
		rtinfo->completion_pid_field = pevent_find_field(event, "pid");
		rtinfo->completion_job_field = pevent_find_field(event, "job");
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_completion_id) {
		pevent_read_number_field(rtinfo->completion_pid_field,
					 record->data, &val);
		*pid = val;
		pevent_read_number_field(rtinfo->completion_job_field,
					 record->data, &val);
		*job = val;
		ret = 1;
	}

	return ret;
}

/**
 * rt_graph_check_task_block - check for litmus_task_block record
 * Return 1 and @pid if the record matches
 */
int rt_graph_check_task_block(struct rt_graph_info *rtinfo,
			      struct pevent *pevent, struct record *record,
			      gint *pid)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->task_block_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_block");
		if (!event)
			return 0;
		rtinfo->task_block_id = event->id;
		rtinfo->block_pid_field = pevent_find_field(event, "pid");
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_block_id) {
		pevent_read_number_field(rtinfo->block_pid_field,
					 record->data, &val);
		*pid = val;
		ret = 1;
	}

	return ret;
}

/**
 * rt_graph_check_task_release - check for litmus_task_release record
 * Return 1 and @pid if the record matches
 */
int rt_graph_check_task_resume(struct rt_graph_info *rtinfo,
			       struct pevent *pevent, struct record *record,
			       gint *pid)
{
	struct event_format *event;
	unsigned long long val;
	gint id;
	int ret = 0;

	if (rtinfo->task_resume_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_resume");
		if (!event)
			return 0;
		rtinfo->task_resume_id = event->id;
		rtinfo->resume_pid_field = pevent_find_field(event, "pid");
	}

	id = pevent_data_type(pevent, record);
	if (id == rtinfo->task_resume_id) {
		pevent_read_number_field(rtinfo->resume_pid_field,
					 record->data, &val);
		*pid = val;
		ret = 1;
	}

	return ret;
}

/**
 * init_rt_event_cache - reset cached field values
 */
void init_rt_event_cache(struct rt_graph_info *rtinfo)
{
	print("hello");
	rtinfo->task_param_id = -1;
	rtinfo->task_release_id = -1;
	rtinfo->task_completion_id = -1;
	rtinfo->task_block_id = -1;
	rtinfo->task_resume_id = -1;

	rtinfo->param_pid_field = NULL;
	rtinfo->param_wcet_field = NULL;
	rtinfo->param_period_field = NULL;

	rtinfo->release_pid_field = NULL;
	rtinfo->release_job_field = NULL;
	rtinfo->release_deadline_field = NULL;

	rtinfo->completion_pid_field = NULL;
	rtinfo->completion_job_field = NULL;

	rtinfo->block_pid_field = NULL;
	rtinfo->resume_pid_field = NULL;
}

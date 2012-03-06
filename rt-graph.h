#ifndef _RT_GRAPH_H
#define _RT_GRAPH_H

#include <gtk/gtk.h>
#include "task-list.h"
#include "trace-cmd.h"
#include "rt-plot-task.h"

#define RT_TS_FIELD "__rt_ts"
#define TS_HASH_SIZE 6
struct ts_list;

struct rt_graph_info {

	/* List of all real-time tasks */
	struct task_list 	*tasks[TASK_HASH_SIZE];

	/* Cache of event fields so that they don't need to be located
	 * during each access.
	 */
	gint 			task_param_id;
	struct format_field 	*param_pid_field;
	struct format_field 	*param_wcet_field;
	struct format_field 	*param_period_field;

	gint			switch_to_id;
	struct format_field	*switch_to_pid_field;
	struct format_field	*switch_to_job_field;
	struct format_field	*switch_to_ts_field;

	gint			switch_away_id;
	struct format_field	*switch_away_pid_field;
	struct format_field	*switch_away_job_field;
	struct format_field	*switch_away_ts_field;

	gint 			task_release_id;
	struct format_field 	*release_pid_field;
	struct format_field 	*release_job_field;
	struct format_field	*release_release_field;
	struct format_field 	*release_deadline_field;

	gint			task_completion_id;
	struct format_field 	*completion_pid_field;
	struct format_field 	*completion_job_field;
	struct format_field	*completion_ts_field;

	gint 			task_block_id;
	struct format_field 	*block_pid_field;
	struct format_field	*block_ts_field;

	gint 			task_resume_id;
	struct format_field 	*resume_pid_field;
	struct format_field	*resume_ts_field;

	/* Cache of ts fields for new events */
	struct ts_list		*events[TS_HASH_SIZE];
};

struct ts_list {
	struct ts_list		*next;
	gint			eid;
	struct format_field	*ts_field;
};

/* Event parsers */
void rt_graph_check_any(struct rt_graph_info *rtinfo,
			struct pevent *pevent, struct record *record,
			gint *epid, unsigned long long *ts);
int rt_graph_check_task_param(struct rt_graph_info *rtinfo, struct pevent *pevent,
			      struct record *record, gint *pid,
			      unsigned long long *wcet,
			      unsigned long long *period);
int rt_graph_check_switch_to(struct rt_graph_info *rtinfo, struct pevent *pevent,
			     struct record *record, gint *pid, gint *job,
			     unsigned long long *when);
int rt_graph_check_switch_away(struct rt_graph_info *rtinfo, struct pevent *pevent,
			       struct record *record, gint *pid, gint *job,
			       unsigned long long *when);
int rt_graph_check_task_release(struct rt_graph_info *rtinfo, struct pevent *pevent,
				struct record *record, gint *pid, gint *job,
				unsigned long long *release,
				unsigned long long *deadline);
int rt_graph_check_task_completion(struct rt_graph_info *rtinfo, struct pevent *pevent,
				   struct record *record, gint *pid, gint *job,
				   unsigned long long *when);
int rt_graph_check_task_block(struct rt_graph_info *rtinfo, struct pevent *pevent,
			      struct record *record, gint *pid,
			      unsigned long long *when);
int rt_graph_check_task_resume(struct rt_graph_info *rtinfo, struct pevent *pevent,
			       struct record *record, gint *pid,
			       unsigned long long *when);
void init_rt_event_cache(struct rt_graph_info *rtinfo);

#endif

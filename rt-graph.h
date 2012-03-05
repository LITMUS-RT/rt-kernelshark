#ifndef _RT_GRAPH_H
#define _RT_GRAPH_H

#include <gtk/gtk.h>
#include "trace-cmd.h"

struct rt_graph_info {

	/* Cache of event fields so that they don't need to be located
	 * during each access.
	 */
	gint 			task_param_id;
	struct format_field 	*param_pid_field;
	struct format_field 	*param_wcet_field;
	struct format_field 	*param_period_field;
	gint 			task_release_id;
	struct format_field 	*release_pid_field;
	struct format_field 	*release_job_field;
	struct format_field 	*release_deadline_field;
	gint			task_completion_id;
	struct format_field 	*completion_pid_field;
	struct format_field 	*completion_job_field;
	gint 			task_block_id;
	struct format_field 	*block_pid_field;
	gint 			task_resume_id;
	struct format_field 	*resume_pid_field;

};

int rt_graph_check_task_param(struct rt_graph_info *rtinfo, struct pevent *pevent,
			      struct record *record, gint *pid,
			      unsigned long long *wcet,
			      unsigned long long *period);
int rt_graph_check_task_release(struct rt_graph_info *rtinfo, struct pevent *pevent,
				struct record *record, gint *pid, gint *job,
				unsigned long long *deadline);
int rt_graph_check_task_completion(struct rt_graph_info *rtinfo, struct pevent *pevent,
				   struct record *record, gint *pid, gint *job);
int rt_graph_check_task_block(struct rt_graph_info *rtinfo, struct pevent *pevent,
			      struct record *record, gint *pid);
int rt_graph_check_task_resume(struct rt_graph_info *rtinfo, struct pevent *pevent,
			       struct record *record, gint *pid);
void init_rt_event_cache(struct rt_graph_info *rtinfo);

#endif

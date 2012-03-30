#ifndef _RT_GRAPH_H
#define _RT_GRAPH_H

#include <gtk/gtk.h>
#include "task-list.h"
#include "trace-cmd.h"
#include "rt-plot.h"
#include "rt-plot-task.h"
#include "rt-plot-cpu.h"
#include "rt-plot-container.h"

#define LLABEL 30
#define SEARCH_PERIODS 5
#define NO_CPU -1
#define RT_TS_FIELD "__rt_ts"

#define TS_HASH_SIZE 12
#define CONT_HASH_SIZE 12

struct ts_list;
struct vcpu_list;

struct rt_graph_info {

	/* List of all real-time tasks */
	struct task_list 	*tasks[TASK_HASH_SIZE];

	/* List of all real-time containers */
	struct cont_list	*containers[CONT_HASH_SIZE];

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

	gint			switch_away_id;
	struct format_field	*switch_away_pid_field;
	struct format_field	*switch_away_job_field;

	gint 			task_release_id;
	struct format_field 	*release_pid_field;
	struct format_field 	*release_job_field;
	struct format_field	*release_release_field;
	struct format_field 	*release_deadline_field;

	gint			task_completion_id;
	struct format_field 	*completion_pid_field;
	struct format_field 	*completion_job_field;

	gint 			task_block_id;
	struct format_field 	*block_pid_field;
	struct format_field 	*block_lid_field;

	gint 			task_resume_id;
	struct format_field 	*resume_pid_field;
	struct format_field 	*resume_lid_field;

	gint			container_param_id;
	struct format_field	*cparam_cid_field;
	struct format_field	*cparam_name_field;

	gint			server_param_id;
	struct format_field	*sparam_sid_field;
	struct format_field	*sparam_cid_field;
	struct format_field	*sparam_wcet_field;
	struct format_field	*sparam_period_field;

	gint			server_switch_to_id;
	struct format_field	*sswitch_to_sid_field;
	struct format_field	*sswitch_to_job_field;
	struct format_field	*sswitch_to_tid_field;

	gint			server_switch_away_id;
	struct format_field	*sswitch_away_sid_field;
	struct format_field	*sswitch_away_job_field;
	struct format_field	*sswitch_away_tid_field;

	gint			server_release_id;
	struct format_field	*srelease_sid_field;
	struct format_field	*srelease_job_field;
	struct format_field	*srelease_release_field;
	struct format_field	*srelease_deadline_field;

	gint			server_completion_id;
	struct format_field	*scompletion_sid_field;
	struct format_field	*scompletion_job_field;

	gint 			server_block_id;
	struct format_field 	*sblock_sid_field;
	struct format_field 	*sblock_lid_field;

	gint 			server_resume_id;
	struct format_field 	*sresume_sid_field;
	struct format_field 	*sresume_lid_field;


	/* Cache of ts fields for non-litmus events */
	struct ts_list		*events[TS_HASH_SIZE];

	/* Used to calculate maximum search times */
	unsigned long long	max_period;
};


/*
 * A list of cached time-stamp fields
 */
struct ts_list {
	struct ts_list		*next;
	gint			eid;
	struct format_field	*ts_field;
};

/*
 * Per-task real-time data
 */
struct rt_task_params {
	unsigned long long	wcet;
	unsigned long long	period;
};

/*
 * A list of servers
 */
struct vcpu_list {
	struct vcpu_list	*next;
	gint			sid;
	struct rt_task_params	params;
};

/*
 * A list of containers
 */
struct cont_list {
	struct cont_list	*next;
	gint			cid;
	gboolean		plotted;
	const char*		name;
	struct vcpu_list	*vcpus;
};

/* Event parsers */
int rt_graph_check_any(struct graph_info *ginfo, struct record *record,
		       gint *pid, gint *eid, unsigned long long *ts);
int rt_graph_check_task_param(struct graph_info *ginfo,
			      struct record *record, gint *pid,
			      unsigned long long *wcet,
			      unsigned long long *period);
int rt_graph_check_switch_to(struct graph_info *ginfo,
			     struct record *record, gint *pid, gint *job,
			     unsigned long long *when);
int rt_graph_check_switch_away(struct graph_info *ginfo,
			       struct record *record, gint *pid, gint *job,
			       unsigned long long *when);
int rt_graph_check_task_release(struct graph_info *ginfo,
				struct record *record, gint *pid, gint *job,
				unsigned long long *release,
				unsigned long long *deadline);
int rt_graph_check_task_completion(struct graph_info *ginfo,
				   struct record *record, gint *pid, gint *job,
				   unsigned long long *when);
int rt_graph_check_task_block(struct graph_info *ginfo,
			      struct record *record, gint *pid, gint *lid,
			      unsigned long long *when);
int rt_graph_check_task_resume(struct graph_info *ginfo, struct record *record,
			       gint *pid, gint *lid, unsigned long long *when);
int rt_graph_check_container_param(struct graph_info *ginfo,
				   struct record *record,
				   gint *cid, char **name);
int rt_graph_check_server_param(struct graph_info *ginfo, struct record *record,
				gint *sid, gint *cid,
				unsigned long long *wcet,
				unsigned long long *period);
int rt_graph_check_server_switch_to(struct graph_info *ginfo,
				    struct record *record,
				    gint *sid, gint *job, gint *tid,
				      unsigned long long *when);
int rt_graph_check_server_switch_away(struct graph_info *ginfo,
				      struct record *record,
				      gint *sid, gint *job, gint *tid,
				      unsigned long long *when);
int rt_graph_check_server_release(struct graph_info *ginfo,
				  struct record *record,
				  gint *sid, gint *job,
				  unsigned long long *release,
				  unsigned long long *deadline);
int rt_graph_check_server_completion(struct graph_info *ginfo,
				     struct record *record,
				     gint *sid, gint *job,
				     unsigned long long *when);
int rt_graph_check_server_block(struct graph_info *ginfo,
				struct record *record, gint *pid, gint *lid,
				unsigned long long *when);
int rt_graph_check_server_resume(struct graph_info *ginfo, struct record *record,
				 gint *pid, gint *lid, unsigned long long *when);
void init_rt_event_cache(struct rt_graph_info *rtinfo);

unsigned long long get_rts(struct graph_info *ginfo,
			   struct record *record);


/* Other */
struct cont_list* find_container(struct cont_list **conts, gint cid, gint key);

static inline void nano_to_milli(unsigned long long time,
				 unsigned long long *msec,
				 unsigned long long *nsec)
{
	*msec = time / 1000000ULL;
	*nsec = time % 1000000ULL;
}

static inline float nano_as_milli(unsigned long long time)
{
	return (float)time / 1000000ULL;
}

static inline int get_container_key(gint cid)
{
	return trace_hash(cid) % CONT_HASH_SIZE;
}

#define max_rt_search(ginfo) (SEARCH_PERIODS*ginfo->rtg_info.max_period)

#endif

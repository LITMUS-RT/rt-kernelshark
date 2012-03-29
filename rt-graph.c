#include <stdio.h>
#include <string.h>
#include "trace-graph.h"
#include "trace-hash.h"

#define DEBUG_LEVEL 4
#if DEBUG_LEVEL > 0
#define dprintf(l, x...)			\
	do {					\
		if (l <= DEBUG_LEVEL)		\
			printf(x);		\
	} while (0)
#else
#define dprintf(l, x...)	do { if (0) printf(x); } while (0)
#endif

static inline guint get_event_hash_key(gint eid)
{
	return trace_hash(eid) % TS_HASH_SIZE;
}

/*
 * Returns string value stored in @field.
 */
static char* read_string_field(struct format_field *field,
			       struct record *record)
{
	char *name, *loc;

	loc = (char*)(record->data + field->offset);
	name = malloc_or_die(field->size);
	snprintf(name, field->size, "%s", loc);
	return name;
}

#define __FIELD(type, name) type##_##name##_field
#define FIELD(rtg, type, name) rtg->__FIELD(type, name)
#define STORE_FIELD(rtg, e, type, name)					\
	do {								\
		FIELD(rtg, type, name) = pevent_find_field(e, #name);	\
	} while (0)
#define LOAD_LONG(rtg, r, type, name, v)				\
	do {								\
		pevent_read_number_field(FIELD(rtg, type, name),	\
					 r->data, v);			\
	} while (0)
#define LOAD_INT(rtg, r, type, name, v)					\
	do {								\
		unsigned long long val;					\
		LOAD_LONG(rtg, r, type, name, &val);			\
		*v = val;						\
	} while (0)
#define LOAD_STRING(rtg, r, type, name, v)				\
	do {								\
		*v = read_string_field(FIELD(rtg, type, name), r);	\
	} while (0)

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
	    struct pevent *pevent,
	    struct record *record)
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
 * Return container for @cid and @key, if present.
 */
struct cont_list*
find_container(struct cont_list **conts, gint cid, gint key)
{
	struct cont_list *list;
	for (list = conts[key]; list; list = list->next) {
		if (list->cid == cid)
			return list;
	}
	return NULL;
}

/*
 * Add and return container with @cid and @name to @conts.
 */
static struct cont_list*
add_container(struct cont_list **conts, gint cid, char *name)
{
	int key;
	struct cont_list *list;

	key = get_container_key(cid);

	list = find_container(conts, cid, key);

	if (!list) {
		list = malloc_or_die(sizeof(*list));
		list->cid = cid;
		list->name = name;
		list->vcpus = NULL;
		list->plotted = FALSE;

		list->next = conts[key];
		conts[key] = list;
	} else {
		free(name);
	}
	return list;
}

/*
 * Add and return server with @sid to container @cid.
 */
static struct vcpu_list*
add_vcpu(struct cont_list **conts,
	 int cid, int sid,
	 unsigned long long wcet, unsigned long long period)
{
	int key;
	struct cont_list *clist;
	struct vcpu_list *vlist, *prev, *next;

	key = get_container_key(cid);
	clist = find_container(conts, cid, key);
	if (!clist)
		die("Cannot add server %d to non-existant container %d!\n",
		       sid, cid);

	for (vlist = clist->vcpus; vlist; vlist = vlist->next) {
		if (vlist->sid == sid)
			return vlist;
	}

	vlist = malloc_or_die(sizeof(*vlist));
	vlist->sid = sid;
	vlist->params.wcet = wcet;
	vlist->params.period = period;

	/* Insert in order */
	if (!clist->vcpus) {
		vlist->next = clist->vcpus;
		clist->vcpus = vlist;
	} else {
		prev = clist->vcpus;
		for (next = prev->next; next; prev = next, next = prev->next) {
			if (sid < next->sid) {
				vlist->next = next;
				prev->next = vlist;
				break;
			}
		}
		if (!next) {
			vlist->next = NULL;
			prev->next = vlist;
		}
	}

	return vlist;
}

/**
 * rt_graph_check_any - parse timestamp of any record
 * @epid: set to the event's task PID
 * @rt_ts: set to the event's real-time timestamp
 */
int rt_graph_check_any(struct graph_info *ginfo,
		       struct record *record,
		       gint *epid, gint *out_eid, unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct format_field *field;
	guint key, eid;

	eid = pevent_data_type(pevent, record);
	key = get_event_hash_key(eid);
	field = find_ts_hash(rtg_info->events, key, eid);

	if (!field)
		field = add_ts_hash(rtg_info->events, eid, key, pevent, record);

	*epid = pevent_data_pid(pevent, record);
	pevent_read_number_field(field, record->data, ts);

	dprintf(3, "Read (%d) record for task %d at %llu\n",
		eid, *epid, *ts);
	*out_eid = eid;
	return 1;
}

/**
 * rt_graph_check_task_param - check for litmus_task_param record
 * Return 1 and @pid, @owcet, and @operiod if the record matches
 */
int rt_graph_check_task_param(struct graph_info *ginfo,
			      struct record *record,
			      gint *pid, unsigned long long *owcet,
			      unsigned long long *operiod)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	struct rt_task_params *params;
	struct task_list *list;
	unsigned long long wcet, period;
	gint id;
	int ret = 0;

	/* Attempt to update record cache. It can only be updated
	 * after the pevent has "seen" its first litmus_task_param
	 * event.
	 */
	if (rtg_info->task_param_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_param");
		if (!event)
			goto out;
		rtg_info->task_param_id = event->id;
		dprintf(2, "Found task_param id %d\n", event->id);
		STORE_FIELD(rtg_info, event, param, pid);
		STORE_FIELD(rtg_info, event, param, wcet);
		STORE_FIELD(rtg_info, event, param, period);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->task_param_id) {
		LOAD_INT(rtg_info, record, param, pid, pid);
		LOAD_LONG(rtg_info, record, param, wcet, &wcet);
		LOAD_LONG(rtg_info, record, param, wcet, &period);

		ret = 1;
		dprintf(3, "Read task_param record for task %d (%llu, %llu)\n",
			*pid, wcet, period);

		list = add_task_hash(rtg_info->tasks, *pid);
		if (!list->data) {
			params = malloc_or_die(sizeof(*params));
			params->wcet = wcet;
			params->period = period;
			list->data = params;
		}

		/* Store max period to calculate max search distance */
		if (period > rtg_info->max_period)
			rtg_info->max_period = period;

		*owcet = wcet;
		*operiod = period;
	}
 out:
	return ret;
}

/**
 * rt_graph_check_switch_to - check for litmus_switch_to record
 * Return 1 and @pid, @job, and @ts if the record matches
 */
int rt_graph_check_switch_to(struct graph_info *ginfo,
			     struct record *record,
			     gint *pid, gint *job,
			     unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->switch_to_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_switch_to");
		if (!event)
			goto out;
		rtg_info->switch_to_id = event->id;
		STORE_FIELD(rtg_info, event, switch_to, pid);
		STORE_FIELD(rtg_info, event, switch_to, job);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->switch_to_id) {
		LOAD_INT(rtg_info, record, switch_to, pid, pid);
		LOAD_INT(rtg_info, record, switch_to, job, job);
		*ts = get_rts(ginfo, record);

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
int rt_graph_check_switch_away(struct graph_info *ginfo,
			       struct record *record,
			       gint *pid, gint *job,
			       unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->switch_away_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_switch_away");
		if (!event)
			goto out;
		rtg_info->switch_away_id = event->id;
		dprintf(2, "Found switch_away id %d\n", event->id);
		STORE_FIELD(rtg_info, event, switch_away, pid);
		STORE_FIELD(rtg_info, event, switch_away, job);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->switch_away_id) {
		LOAD_INT(rtg_info, record, switch_away, pid, pid);
		LOAD_INT(rtg_info, record, switch_away, job, job);
		*ts = get_rts(ginfo, record);

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
int rt_graph_check_task_release(struct graph_info *ginfo,
				struct record *record,
				gint *pid, gint *job,
				unsigned long long *release,
				unsigned long long *deadline)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->task_release_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_release");
		if (!event)
			goto out;
		rtg_info->task_release_id = event->id;
		dprintf(2, "Found task_release id %d\n", event->id);
		STORE_FIELD(rtg_info, event, release, pid);
		STORE_FIELD(rtg_info, event, release, job);
		STORE_FIELD(rtg_info, event, release, release);
		STORE_FIELD(rtg_info, event, release, deadline);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->task_release_id) {
		LOAD_INT(rtg_info, record, release, pid, pid);
		LOAD_INT(rtg_info, record, release, job, job);
		LOAD_LONG(rtg_info, record, release, release, release);
		LOAD_LONG(rtg_info, record, release, deadline, deadline);

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
int rt_graph_check_task_completion(struct graph_info *ginfo,
				   struct record *record,
				   gint *pid, gint *job, unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->task_completion_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_completion");
		if (!event)
			goto out;
		rtg_info->task_completion_id = event->id;
		dprintf(2, "Found task_completion id %d\n", event->id);
		STORE_FIELD(rtg_info, event, completion, pid);
		STORE_FIELD(rtg_info, event, completion, job);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->task_completion_id) {
		LOAD_INT(rtg_info, record, completion, pid, pid);
		LOAD_INT(rtg_info, record, completion, job, job);

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
int rt_graph_check_task_block(struct graph_info *ginfo,
			      struct record *record,
			      gint *pid, unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->task_block_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_block");
		if (!event)
			goto out;
		dprintf(2, "Found task_block id %d\n", event->id);
		STORE_FIELD(rtg_info, event, block, pid);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->task_block_id) {
		LOAD_INT(rtg_info, record, block, pid, pid);
		*ts = get_rts(ginfo, record);

		ret = 1;
		dprintf(3, "Read task_block (%d) record for task %d\n",
			id, *pid);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_task_resume - check for litmus_task_resume record
 * Return 1, @pid, and @ts if the record matches
 */
int rt_graph_check_task_resume(struct graph_info *ginfo,
			       struct record *record,
			       gint *pid, unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->task_resume_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_task_resume");
		if (!event)
			goto out;
		dprintf(2, "Found task_resume id %d\n", event->id);
		STORE_FIELD(rtg_info, event, resume, pid);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->task_resume_id) {
		LOAD_INT(rtg_info, record, resume, pid, pid);
		*ts = get_rts(ginfo, record);

		ret = 1;
		dprintf(3, "Read task_resume (%d) record for task %d\n",
			id, *pid);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_container_param - check for litmus_container_param record
 * Return 1, @cid, and @name if the record matches
 */
int rt_graph_check_container_param(struct graph_info *ginfo,
				   struct record *record,
				   gint *cid, char **name)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->container_param_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_container_param");
		if (!event)
			goto out;
		rtg_info->container_param_id = event->id;
		dprintf(2, "Found container_param id %d\n", event->id);
		STORE_FIELD(rtg_info, event, cparam, cid);
		STORE_FIELD(rtg_info, event, cparam, name);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->container_param_id) {
		LOAD_INT(rtg_info, record, cparam, cid, cid);
		LOAD_STRING(rtg_info, record, cparam, name, name);

		add_container(rtg_info->containers, *cid, *name);

		dprintf(3, "Read container_param for %s - %d\n",
			*name, *cid);
		ret = 1;
	}
 out:
	return ret;
}

/**
 * rt_graph_check_server_param - check for litmus_server_param record
 * Return 1, @sid, @ocid, @owcet, and @operiod if the record matches
 */
int rt_graph_check_server_param(struct graph_info *ginfo, struct record *record,
				gint *sid, gint *ocid,
				unsigned long long *owcet,
				unsigned long long *operiod)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	unsigned long long wcet, period;
	gint cid, id;
	int ret = 0;

	if (rtg_info->server_param_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_server_param");
		if (!event)
			goto out;
		rtg_info->server_param_id = event->id;
		dprintf(2, "Found server_param id %d\n", event->id);
		STORE_FIELD(rtg_info, event, sparam, cid);
		STORE_FIELD(rtg_info, event, sparam, sid);
		STORE_FIELD(rtg_info, event, sparam, wcet);
		STORE_FIELD(rtg_info, event, sparam, period);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->server_param_id) {
		LOAD_INT(rtg_info, record, sparam, sid, sid);
		LOAD_INT(rtg_info, record, sparam, cid, &cid);
		LOAD_LONG(rtg_info, record, sparam, wcet, &wcet);
		LOAD_LONG(rtg_info, record, sparam, period, &period);

		add_vcpu(rtg_info->containers, cid, *sid, wcet, period);

		ret = 1;
		dprintf(3, "Read server_param record for server %d "
			"(%llu, %llu) in container %d\n",
			*sid, wcet, period, cid);
		*ocid = cid;
		*owcet = wcet;
		*operiod = period;
	}
 out:
	return ret;
}

/**
 * rt_graph_check_server_switch_to - check for litmus_server_switch_to record
 * Return 1, @sid, @job, @tid, and @ts if the record matches
 */
int rt_graph_check_server_switch_to(struct graph_info *ginfo,
				    struct record *record,
				    gint *sid, gint *job, gint *tid,
				    unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->server_switch_to_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_server_switch_to");
		if (!event)
			goto out;
		rtg_info->server_switch_to_id = event->id;
		dprintf(2, "Found server_switch_to id %d\n", event->id);
		STORE_FIELD(rtg_info, event, sswitch_to, sid);
		STORE_FIELD(rtg_info, event, sswitch_to, job);
		STORE_FIELD(rtg_info, event, sswitch_to, tid);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->server_switch_to_id) {
		LOAD_INT(rtg_info, record, sswitch_to, sid, sid);
		LOAD_INT(rtg_info, record, sswitch_to, job, job);
		LOAD_INT(rtg_info, record, sswitch_to, tid, tid);
		*ts = get_rts(ginfo, record);

		dprintf(3, "Read server_switch_to(job(%d, %d)): %d",
			*sid, *job, *tid);
		ret = 1;
	}
 out:
	return ret;
}

/**
 * rt_graph_check_server_switch_away - check for litmus_server_switch_away
 * Return 1, @sid, @job, @tid, and @ts if the record matches
 */
int rt_graph_check_server_switch_away(struct graph_info *ginfo,
				      struct record *record,
				      gint *sid, gint *job, gint *tid,
				      unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->server_switch_away_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_server_switch_away");
		if (!event)
			goto out;
		rtg_info->server_switch_away_id = event->id;
		dprintf(2, "Found server_switch_away id %d\n", event->id);
		STORE_FIELD(rtg_info, event, sswitch_away, sid);
		STORE_FIELD(rtg_info, event, sswitch_away, job);
		STORE_FIELD(rtg_info, event, sswitch_away, tid);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->server_switch_away_id) {
		LOAD_INT(rtg_info, record, sswitch_away, sid, sid);
		LOAD_INT(rtg_info, record, sswitch_away, job, job);
		LOAD_INT(rtg_info, record, sswitch_away, tid, tid);
		*ts = get_rts(ginfo, record);


		dprintf(3, "Read server_switch_away(job(%d, %d)): %d",
			*sid, *job, *tid);
		ret = 1;
	}
 out:
	return ret;
}

/**
 * rt_graph_check_server_release - check for litmus_server_release
 * Return 1, @sid, @job, @release, and @deadline if the record matches
 */
int rt_graph_check_server_release(struct graph_info *ginfo,
				  struct record *record,
				  gint *sid, gint *job,
				  unsigned long long *release,
				  unsigned long long *deadline)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->server_release_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_server_release");
		if (!event)
			goto out;
		rtg_info->server_release_id = event->id;
		dprintf(2, "Found server_switch_away id %d\n", event->id);
		STORE_FIELD(rtg_info, event, srelease, sid);
		STORE_FIELD(rtg_info, event, srelease, job);
		STORE_FIELD(rtg_info, event, srelease, release);
		STORE_FIELD(rtg_info, event, srelease, deadline);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->server_release_id) {
		LOAD_INT(rtg_info, record, srelease, sid, sid);
		LOAD_INT(rtg_info, record, srelease, job, job);
		LOAD_LONG(rtg_info, record, srelease, release, release);
		LOAD_LONG(rtg_info, record, srelease, deadline, deadline);

		dprintf(3, "Read server_switch_release(job(%d, %d)), rel: %llu,"
			" dead: %llu\n", *sid, *job, *release, *deadline);
		ret = 1;
	}
 out:
	return ret;
}

/**
 * rt_graph_check_server_completion - check for litmus_server_completion record
 * Return 1, @sid, and @job if the record matches
 */
int rt_graph_check_server_completion(struct graph_info *ginfo,
				     struct record *record,
				     gint *sid, gint *job,
				     unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->server_completion_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_server_completion");
		if (!event)
			goto out;
		rtg_info->server_completion_id = event->id;
		dprintf(2, "Found server_switch_away id %d\n", event->id);
		STORE_FIELD(rtg_info, event, scompletion, sid);
		STORE_FIELD(rtg_info, event, scompletion, job);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->server_completion_id) {
		LOAD_INT(rtg_info, record, scompletion, sid, sid);
		LOAD_INT(rtg_info, record, scompletion, job, job);
		*ts = get_rts(ginfo, record);

		dprintf(3, "Read server_completion(job(%d, %d))\n", *sid, *job);
		ret = 1;
	}
 out:
	return ret;
}


/**
 * rt_graph_check_server_block - check for litmus_server_block record
 * Return 1, @sid, and @ts if the record matches
 */
int rt_graph_check_server_block(struct graph_info *ginfo,
				struct record *record,
				gint *sid, unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->server_block_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_server_block");
		if (!event)
			goto out;
		dprintf(2, "Found server_block id %d\n", event->id);
		STORE_FIELD(rtg_info, event, sblock, sid);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->server_block_id) {
		LOAD_INT(rtg_info, record, sblock, sid, sid);
		*ts = get_rts(ginfo, record);

		ret = 1;
		dprintf(3, "Read server_block record for server %d\n", *sid);
	}
 out:
	return ret;
}

/**
 * rt_graph_check_server_resume - check for litmus_server_resume record
 * Return 1, @sid, and @ts if the record matches
 */
int rt_graph_check_server_resume(struct graph_info *ginfo,
				 struct record *record,
				 gint *sid, unsigned long long *ts)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct pevent *pevent = ginfo->pevent;
	struct event_format *event;
	gint id;
	int ret = 0;

	if (rtg_info->server_resume_id < 0) {
		event = pevent_find_event_by_name(pevent, "litmus",
						  "litmus_server_resume");
		if (!event)
			goto out;
		dprintf(2, "Found server_resume id %d\n", event->id);
		STORE_FIELD(rtg_info, event, sresume, sid);
	}

	id = pevent_data_type(pevent, record);
	if (id == rtg_info->server_resume_id) {
		LOAD_INT(rtg_info, record, sresume, sid, sid);
		*ts = get_rts(ginfo, record);

		ret = 1;
		dprintf(3, "Read server_resume record for server %d\n", *sid);
	}
 out:
	return ret;
}


/**
 * init_rt_event_cache - reset cached field values
 */
void init_rt_event_cache(struct rt_graph_info *rtg_info)
{
	dprintf(1, "Initializing RT event cache\n");

	memset(rtg_info, 0, sizeof(*rtg_info));

	rtg_info->task_param_id = -1;
	rtg_info->switch_to_id = -1;
	rtg_info->switch_away_id = -1;
	rtg_info->task_release_id = -1;
	rtg_info->task_completion_id = -1;
	rtg_info->task_block_id = -1;
	rtg_info->task_resume_id = -1;

	rtg_info->container_param_id = -1;
	rtg_info->server_param_id = -1;
	rtg_info->server_switch_to_id = -1;
	rtg_info->server_switch_away_id = -1;
	rtg_info->server_release_id = -1;
	rtg_info->server_completion_id = -1;
	rtg_info->server_block_id = -1;
	rtg_info->server_resume_id = -1;
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
		rt_graph_check_any(ginfo, record, &epid, &eid, &ts);
		record->cached_rts = ts;
	} else
		ts = record->cached_rts;
	return ts;
}

#include <string.h>
#include "trace-graph.h"
#include "cpu.h"

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
 * Return the next switch_away record after @time.
 */
static struct record*
next_sa_record(struct graph_info *ginfo, struct rt_cpu_info *rtc_info,
	       unsigned long long time, int *out_pid)
{
	struct pevent *pevent;
	struct record *ret = NULL, *record;
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	unsigned long long max_ts, dull;
	int pid, dint, match;

	max_ts = time + SEARCH_PERIODS * rtg_info->max_period;
	pevent = ginfo->pevent;

	set_cpu_to_rts(ginfo, time, rtc_info->cpu);

	while ((record = tracecmd_read_data(ginfo->handle, rtc_info->cpu))) {
		if (get_rts(ginfo, record) > max_ts) {
			free_record(record);
			break;
		}
		match = rt_graph_check_switch_away(ginfo, record,
						   &pid, &dint, &dull);
		if (match) {
			ret = record;
			*out_pid = pid;
			break;
		}
		free_record(record);
	}
	return ret;
}

/*
 * Return 1 if the name of @eid is displayed in the plot.
 */
static inline int
is_displayed(struct graph_info *ginfo, int eid)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	return (eid == rtg_info->switch_away_id     ||
		eid == rtg_info->switch_to_id       ||
		eid == ginfo->event_sched_switch_id);
}

static struct record*
__find_record(struct graph_info *ginfo, int cpu, unsigned long long time,
	      int display)
{
	struct record *record;
	int eid, ignored;

	set_cpu_to_rts(ginfo, time, cpu);

	while ((record = tracecmd_read_data(ginfo->handle, cpu))) {
		ignored = 0;
		eid = pevent_data_type(ginfo->pevent, record);

		if (display)
			ignored = is_displayed(ginfo, eid);

		if (get_rts(ginfo, record) >= time && !ignored)
			break;
		free_record(record);
	}
	return record;
}

/*
 * Return the first record after @time on @cpu.
 */
static inline struct record*
find_record(struct graph_info *ginfo, int cpu, guint64 time)
{
	return __find_record(ginfo, cpu, time, 0);
}

/*
 * Return the first _displayed_ record after @time on @cpu.
 */
static inline struct record*
find_display_record(struct graph_info *ginfo, int cpu, guint64 time)
{
	return __find_record(ginfo, cpu, time, 1);
}

/*
 * Update fields in @rtc_info for the new @pid.
 */
static void update_pid(struct rt_cpu_info *rtc_info, int pid)
{
	rtc_info->fresh = FALSE;
	if (pid != rtc_info->run_pid) {
		rtc_info->run_pid = pid;
		snprintf(rtc_info->label, LLABEL, "%d", rtc_info->run_pid);
	}
}

/*
 * Get information about the given @time.
 * @out_pid: The running pid at @time
 * @out_job: The running job at @time
 * @out_record: The record at @time
 *
 * Return 1, @out_pid, and @out_job if the CPU is running at @time.
 */
static int get_time_info(struct graph_info *ginfo,
			 struct rt_cpu_info *rtc_info,
			 unsigned long long time,
			 int *out_pid, int *out_job,
			 struct record **out_record)
{
	struct record *record;
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	unsigned long long dull, max_ts;
	const char *comm;
	int cpu, is_running, pid, job;

	cpu = rtc_info->cpu;
	*out_pid = *out_job = is_running = 0;

	/* TODO: inneficient */
	*out_record = find_display_record(ginfo, cpu, time);
	record = find_record(ginfo, cpu, time);
	if (!record)
		goto out;

	max_ts = time + SEARCH_PERIODS * rtg_info->max_period;
	do {
		if (get_rts(ginfo, record) > max_ts)
			break;

#define ARG ginfo, record, &pid, &job, &dull
		if (rt_graph_check_switch_to(ARG) && pid) {
			goto out;
		} else if (rt_graph_check_switch_away(ARG) && pid) {
			is_running = 1;
			*out_pid = pid;
			*out_job = job;
			goto out;
		} else if (trace_graph_check_sched_switch(ginfo, record,
							  &pid, &comm)) {
			pid = pevent_data_pid(ginfo->pevent, record);
			if (pid) {
				*out_pid = pid;
				*out_job = 0;
				is_running = 1;
				goto out;
			}
		}
		if (*out_record != record)
			free_record(record);
#undef ARG
	} while ((record = tracecmd_read_data(ginfo->handle, cpu)));
 out:
	if (*out_record != record)
		free_record(record);
	return is_running;
}

static int
try_switch_away(struct graph_info *ginfo, struct rt_cpu_info *rtc_info,
		struct record *record, struct plot_info *info)
{
	int job, pid, match;
	unsigned long long ts;

	match = rt_graph_check_switch_away(ginfo, record,  &pid, &job, &ts);
	match = match && pid;
	if (match) {
		update_pid(rtc_info, pid);
		if (rtc_info->rt_run_time && rtc_info->rt_run_time < ts &&
		    job != 1) {
			info->box = TRUE;
			info->bcolor = hash_pid(rtc_info->run_pid);
			info->bfill = TRUE;
			info->bstart = rtc_info->rt_run_time;
			info->bend = ts;
			info->blabel = rtc_info->label;
		}
		rtc_info->run_pid = 0;
		rtc_info->rt_run_time = 0Ull;
		rtc_info->reg_run_time = 0ULL;
	}
	return match;
}

static int
try_switch_to(struct graph_info *ginfo, struct rt_cpu_info *rtc_info,
	      struct record *record, struct plot_info *info)
{
	int job, pid, match;
	unsigned long long ts;

	match = rt_graph_check_switch_to(ginfo, record, &pid, &job, &ts);
	match = match && pid;
	if (match) {
		update_pid(rtc_info, pid);
		rtc_info->rt_run_time = ts;
		rtc_info->reg_run_time = 0ULL;
	}
	return match;
}

static int
try_completion(struct graph_info *ginfo, struct rt_cpu_info *rtc_info,
		struct record *record, struct plot_info *info)
{
	int pid, job, match;
	unsigned long long ts;

	match = rt_graph_check_task_completion(ginfo, record, &pid, &job, &ts);
	if (match) {
		info->completion = TRUE;
		info->ctime = ts;
	}
	return match;
}

static int
try_sched_switch(struct graph_info *ginfo, struct rt_cpu_info *rtc_info,
		 struct record *record, struct plot_info *info)
{
	const char *comm;
	int from_pid, to_pid, match;

	match = trace_graph_check_sched_switch(ginfo, record, &to_pid, &comm);
	if (match) {
		from_pid = pevent_data_pid(ginfo->pevent, record);
		/* Only draw if no real-time task is running */
		if (!rtc_info->rt_run_time) {
			if (rtc_info->reg_run_time &&
			    rtc_info->reg_run_time < get_rts(ginfo, record) &&
			    from_pid) {
				/* A non-rt task was running */
				info->box = TRUE;
				info->bthin = TRUE;
				info->bcolor = 0x0;
				info->bstart = rtc_info->reg_run_time;
				info->bend = get_rts(ginfo, record);
			}
			if (to_pid)
				rtc_info->reg_run_time = get_rts(ginfo, record);
			else
				rtc_info->reg_run_time = 0ULL;
		}
		update_pid(rtc_info, to_pid);
	}
	return match;
}

static void do_plot_end(struct graph_info *ginfo, struct rt_cpu_info *rtc_info,
			struct plot_info *info)
{
	int pid;
	struct record *record;

	if (ginfo->view_end_time == ginfo->end_time)
		return;

	if (rtc_info->rt_run_time && rtc_info->run_pid) {
		info->box = TRUE;
		info->bcolor = hash_pid(rtc_info->run_pid);
		info->bfill = TRUE;
		info->bstart = rtc_info->rt_run_time;
		info->bend = ginfo->view_end_time;
		info->blabel = rtc_info->label;
		rtc_info->fresh = FALSE;
	} else if (rtc_info->fresh) {
		record = next_sa_record(ginfo, rtc_info,
					ginfo->view_end_time,
					&pid);
		if (record) {
			update_pid(rtc_info, pid);
			info->box = TRUE;
			info->bcolor = hash_pid(pid);
			info->bfill = TRUE;
			info->blabel = rtc_info->label;
			info->bstart = ginfo->view_start_time;
			info->bend = ginfo->view_end_time;
			rtc_info->fresh = FALSE;
		}
		free_record(record);
	}
}

static int rt_cpu_plot_match_time(struct graph_info *ginfo,
				  struct graph_plot *plot,
				  unsigned long long time)
{
	int ret = 0;
	struct rt_cpu_info *rtc_info = plot->private;
	struct record *record = find_record(ginfo, rtc_info->cpu, time);

	if (record && get_rts(ginfo, record) == time)
		ret = 1;
	free_record(record);

	return ret;
}

static void rt_cpu_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
			      unsigned long long time)
{
	struct rt_cpu_info *rtc_info = plot->private;

	rtc_info->rt_run_time = time;
	rtc_info->reg_run_time = time;
	rtc_info->run_pid = 0;
	rtc_info->fresh = TRUE;
}

static int rt_cpu_plot_event(struct graph_info *ginfo, struct graph_plot *plot,
			     struct record *record, struct plot_info *info)
{
	int pid = 0, eid, match, dint;
	unsigned long long ts, dull;
	char *dchar;
	struct rt_cpu_info *rtc_info = plot->private;

	if (!record) {
		do_plot_end(ginfo, rtc_info, info);
		return 0;
	}

	if (record->cpu != rtc_info->cpu)
		return 0;

	match = try_switch_away(ginfo, rtc_info, record, info) ||
		try_switch_to(ginfo, rtc_info, record, info)   ||
		try_sched_switch(ginfo, rtc_info, record, info);

	if (is_high_res(ginfo)) {
		match = match || try_completion(ginfo, rtc_info, record, info);

	}

	if (!match) {
		/* TODO: this should not be necessary!
		 * Have to call checks to ensure ids are loaded. Otherwise,
		 * is_displayed will not work here or in any other methods.
		 */
#define ARG ginfo,record, &pid
		rt_graph_check_task_param(ARG, &dull, &dull) ||
		rt_graph_check_container_param(ARG, &dchar)  ||
		rt_graph_check_server_param(ARG, &dint, &dull, &dull) ||
		rt_graph_check_task_release(ARG, &dint, &dull, &dull) ||
		rt_graph_check_task_block(ARG, &dint, &dull)   ||
		rt_graph_check_task_resume(ARG, &dint,  &dull) ||
		rt_graph_check_any(ARG, &eid, &ts);
#undef ARG

		if (!is_displayed(ginfo, eid)) {
			info->line = TRUE;
			info->lcolor = hash_pid(pid);
			info->ltime = ts;
		}
	}
	return 1;
}

static int
rt_cpu_plot_display_last_event(struct graph_info *ginfo, struct graph_plot *plot,
			  struct trace_seq *s, unsigned long long time)
{
	struct rt_cpu_info *rtc_info = plot->private;
	struct event_format *event;
	struct record *record;
	unsigned long long offset;
	int eid, cpu;

	cpu = rtc_info->cpu;
	record = tracecmd_peek_data(ginfo->handle, cpu);
	if (record)
		offset = record->offset;

	record = find_display_record(ginfo, cpu, time);

	if (offset)
		tracecmd_set_cursor(ginfo->handle, cpu, offset);
	if (!record)
		return 0;

	eid = pevent_data_type(ginfo->pevent, record);
	event = pevent_data_event_from_type(ginfo->pevent, eid);
	if (event) {
		trace_seq_puts(s, event->name);
		trace_seq_printf(s, "\n"); /* Doesn't work otherwise */
	} else
		trace_seq_printf(s, "UNKNOWN EVENT %d\n", eid);
	free_record(record);

	return 1;
}

struct record*
rt_cpu_plot_find_record(struct graph_info *ginfo, struct graph_plot *plot,
		   unsigned long long time)
{
	struct rt_cpu_info *rtc_info = plot->private;
	return find_record(ginfo, rtc_info->cpu, time);
}

static int
rt_cpu_plot_display_info(struct graph_info *ginfo, struct graph_plot *plot,
		    struct trace_seq *s, unsigned long long time)
{
	struct rt_cpu_info *rtc_info = plot->private;
	unsigned long long msec, nsec, rts;
	int pid, eid, job, is_running;
	struct record *record;
	struct event_format *event;
	const char *comm;

	is_running = get_time_info(ginfo, rtc_info, time,
				   &pid, &job, &record);

	if (is_running) {
		comm = pevent_data_comm_from_pid(ginfo->pevent, pid);
		trace_seq_printf(s, "%s-%d:%d\n\n", comm, pid, job);
	}

	if (record) {
		rts = get_rts(ginfo, record);
		if (in_res(ginfo, rts, time)) {
			eid = pevent_data_type(ginfo->pevent, record);
			event = pevent_data_event_from_type(ginfo->pevent, eid);
			if (event) {
				trace_seq_puts(s, event->name);
				trace_seq_putc(s, '\n');
				pevent_event_info(s, event, record);
				trace_seq_putc(s, '\n');
				if (!is_running)
					trace_seq_putc(s, '\n');
			} else
				trace_seq_printf(s, "UNKNOWN EVENT %d\n", eid);
		}
		free_record(record);
	}
	nano_to_milli(time, &msec, &nsec);
	trace_seq_printf(s, "%llu.%06llu ms CPU: %03d",
			 msec, nsec, rtc_info->cpu);

	return 1;
}

static void rt_cpu_plot_destroy(struct graph_info *ginfo, struct graph_plot *plot)
{
	struct rt_cpu_info *rtc_info = plot->private;

	trace_graph_plot_remove_all_recs(ginfo, plot);
	free(rtc_info->label);
	free(rtc_info);
}

const struct plot_callbacks rt_cpu_cb = {
	.start			= rt_cpu_plot_start,
	.destroy		= rt_cpu_plot_destroy,
	.plot_event		= rt_cpu_plot_event,
	.display_last_event	= rt_cpu_plot_display_last_event,
	.display_info		= rt_cpu_plot_display_info,
	.match_time		= rt_cpu_plot_match_time,
	.find_record		= rt_cpu_plot_find_record,
};

void rt_plot_cpus_update_callback(gboolean accept,
				  gboolean all_cpus,
				  guint64 *selected_cpu_mask,
				  gpointer data)
{
	struct graph_info *ginfo = data;
	struct rt_cpu_info *rtc_info;
	struct graph_plot *plot;
	gboolean old_all_cpus;
	guint64 *old_cpu_mask;
	int i;

	if (!accept)
		return;

	/* Get the current status */
	rt_plot_cpus_plotted(ginfo, &old_all_cpus, &old_cpu_mask);

	if (old_all_cpus == all_cpus ||
	    (selected_cpu_mask &&
	     cpus_equal(old_cpu_mask, selected_cpu_mask, ginfo->cpus))) {
		/* Nothing to do */
		g_free(old_cpu_mask);
		return;
	}

	if (!all_cpus) {
		/*
		 * Remove any plots not selected.
		 * Go backwards, since removing a plot shifts the
		 * array from current position back.
		 */
		for (i = ginfo->plots - 1; i >= 0; i--) {
			plot = ginfo->plot_array[i];
			if (plot->type != PLOT_TYPE_CPU)
				continue;
			rtc_info = plot->private;
			if (!cpu_isset(selected_cpu_mask, rtc_info->cpu)) {
				trace_graph_plot_remove(ginfo, plot);
				trace_graph_plot_remove_cpu(ginfo, plot,
							    rtc_info->cpu);
			}
		}
	}

	/* Now add any plots not set */
	for (i = 0; i < ginfo->cpus; i++) {
		if (!all_cpus && !cpu_isset(selected_cpu_mask, i))
			continue;
		if (cpu_isset(old_cpu_mask, i))
			continue;
		rt_plot_cpu(ginfo, i);
	}

	g_free(old_cpu_mask);

	trace_graph_refresh(ginfo);
}

/**
 * rt_plot_cpus_plotted - return the cpus plotted.
 */
void rt_plot_cpus_plotted(struct graph_info *ginfo,
			 gboolean *all_cpus, guint64 **cpu_mask)
{
	struct rt_cpu_info *rtc_info;
	struct graph_plot *plot;
	int i;

	*cpu_mask = g_new0(guint64, (ginfo->cpus >> 6) + 1);
	g_assert(*cpu_mask);

	for (i = 0; i < ginfo->plots; i++) {
		plot = ginfo->plot_array[i];
		if (plot->type != PLOT_TYPE_RT_CPU)
			continue;
		rtc_info = plot->private;
		cpu_set(*cpu_mask, rtc_info->cpu);
	}

	*all_cpus = cpu_weight(*cpu_mask, ginfo->cpus) == ginfo->cpus ?
		TRUE : FALSE;
}

/**
 * rt_plot_cpu_label - create a plot for @cpu with @label.
 */
void rt_plot_cpu_label(struct graph_info *ginfo, int cpu, char* label)
{
	struct rt_cpu_info *rtc_info;
	struct graph_plot *plot;

	rtc_info = malloc_or_die(sizeof(*rtc_info));
	memset(rtc_info, 0, sizeof(*rtc_info));
	rtc_info->cpu = cpu;
	rtc_info->label = label;

	plot = trace_graph_plot_append(ginfo, label, PLOT_TYPE_RT_CPU,
				       TIME_TYPE_RT, &rt_cpu_cb, rtc_info);
	trace_graph_plot_add_all_recs(ginfo, plot);

	trace_graph_plot_add_cpu(ginfo, plot, cpu);
}

/**
 * rt_plot_cpu - create a plot for @cpu.
 */
void rt_plot_cpu(struct graph_info *ginfo, int cpu)
{
	char *label = malloc_or_die(LLABEL);
	snprintf(label, 100, "RT-CPU %d", cpu);
	rt_plot_cpu_label(ginfo, cpu, label);
}

void rt_plot_init_cpus(struct graph_info *ginfo, int cpus)
{
	long cpu;
	for (cpu = 0; cpu < cpus; cpu++)
		rt_plot_cpu(ginfo, cpu);
}

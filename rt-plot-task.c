#include "trace-graph.h"

#define LLABEL 30

/* Ok to do it this way as long as it remains single threaded */
static void update_job(struct rt_task_info *rtt_info, int job)
{
	if (job < rtt_info->last_job) {
		die("Inconsistent job state for %d:%d -> %d\n",
		    rtt_info->base.pid, rtt_info->last_job, job);
	}
	if (job > rtt_info->last_job) {
		rtt_info->last_job = job;
		snprintf(rtt_info->label, LLABEL, "%d:%d",
			 rtt_info->base.pid, rtt_info->last_job);
	}
}

static inline void create_job_label(char *label, int pid, int job)
{
	label = malloc_or_die(20);
	snprintf(label, 20, "%d:%d", pid, job);
}

static int try_param(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		     struct record *record, struct plot_info *info)
{
	int pid, match, ret = 0;
	unsigned long long wcet, period;

	/* Only 1 param record per event */
	if (rtt_info->params_found)
		goto out;

	match = rt_graph_check_task_param(&ginfo->rtinfo, ginfo->pevent,
					  record, &pid, &wcet, &period);
	if (match && pid == rtt_info->base.pid) {
		rtt_info->wcet = wcet;
		rtt_info->period = period;
		rtt_info->params_found = TRUE;
		update_job(rtt_info, 0);
		ret = 1;
	}
 out:
	return ret;
}


static int try_release(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		       struct record *record, struct plot_info *info)
{
	int pid, job, match, ret = 0;
	unsigned long long release, deadline;

	match = rt_graph_check_task_release(&ginfo->rtinfo, ginfo->pevent,
					    record, &pid, &job,
					    &release, &deadline);
	if (match && pid == rtt_info->base.pid) {
		info->release = TRUE;
		info->rtime = release;
		info->rlabel = rtt_info->label;

		info->deadline = TRUE;
		info->dtime = deadline;
		info->dlabel = rtt_info->label;

		update_job(rtt_info, job);
		ret = 1;
	}
	return ret;
}

static int try_completion(struct graph_info *ginfo,
			  struct rt_task_info *rtt_info,
			  struct record *record, struct plot_info *info)
{
	int pid, job, match, ret = 0;
	unsigned long long when;

	match = rt_graph_check_task_completion(&ginfo->rtinfo, ginfo->pevent,
					       record, &pid, &job, &when);
	if (match && pid == rtt_info->base.pid) {
		info->completion = TRUE;
		info->ctime = when;
		info->clabel = rtt_info->label;
		update_job(rtt_info, job);
		ret = 1;
	}
	return ret;
}

static int try_block(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		     struct record *record, struct plot_info *info)
{
	int pid, match, ret = 0;
	unsigned long long when;

	match = rt_graph_check_task_block(&ginfo->rtinfo, ginfo->pevent,
					  record, &pid, &when);
	if (match && pid == rtt_info->base.pid) {
		rtt_info->block_time = when;
		ret = 1;
	}
	return ret;
}

static int try_resume(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		      struct record *record, struct plot_info *info)
{
	int pid, match, ret = 0;
	unsigned long long when;

	match = rt_graph_check_task_resume(&ginfo->rtinfo, ginfo->pevent,
					   record, &pid, &when);
	if (match && pid == rtt_info->base.pid) {
		rtt_info->block_time = when;
		info->box = TRUE;
		info->bcolor = 0x0;
		info->bfill = TRUE;
		info->bthin = TRUE;
		info->bstart = rtt_info->block_time;
		info->bend = when;

		rtt_info->block_time = -1;

		ret = 1;
	}
	return ret;
}

static int try_other(struct graph_info *ginfo, struct rt_task_info *rtt_info,
		     struct record *record, struct plot_info *info)
{
	int pid, is_sched, is_wakeup, rec_pid, sched_pid, match, ret = 0;
	struct task_plot_info *task_info = &rtt_info->base;

	pid = task_info->pid;
	match = record_matches_pid(ginfo, record, pid, &rec_pid,
				   &sched_pid, &is_sched, &is_wakeup);
	if (match) {
		info->line = TRUE;
		info->lcolor = hash_pid(rec_pid);
		info->ltime = record->ts;
		ret = 1;

		update_last_task_record(ginfo, task_info, record);

		if (is_wakeup) {
			/* Another task is running on this CPU now */
			info->ltime = hash_pid(rec_pid);
			if (task_info->last_cpu == record->cpu) {
				info->box = TRUE;
				info->bcolor = hash_cpu(task_info->last_cpu);
				info->bstart = task_info->last_time;
				info->bend = record->ts;
				task_info->last_cpu = -1;
			}
			goto out;
		}

		if (task_info->last_cpu != record->cpu) {
			/* Switched cpus */
			if (task_info->last_cpu >= 0) {
				info->box = TRUE;
				info->bcolor = hash_cpu(task_info->last_cpu);
				info->bstart = task_info->last_time;
				info->bend = record->ts;
			}
			task_info->last_time = record->ts;
		}

		task_info->last_cpu = record->cpu;
		if (is_sched) {
			if (rec_pid != pid) {
				/* Scheduled in */
				task_info->last_cpu = record->cpu;
				task_info->last_time = record->ts;
			} else if (!info->box) {
				/* Scheduled out */
				info->box = TRUE;
				info->bcolor = hash_cpu(task_info->last_cpu);
				info->bstart = task_info->last_time;
				info->bend = record->ts;
				task_info->last_cpu = -1;
			}
		}
	}
 out:
	if (info->box) {
		info->blabel = rtt_info->label;
	}
	return ret;
}

int rt_task_plot_event(struct graph_info *ginfo, struct graph_plot *plot,
		       struct record *record, struct plot_info *info)
{
	struct rt_task_info *rtt_info = plot->private;
	struct task_plot_info *task_info = &rtt_info->base;
	int match, cpu;

	/* No more records, finish what we started */
	if (!record) {
		update_last_task_record(ginfo, task_info, record);
		if (task_info->last_cpu >= 0) {
			info->box = TRUE;
			info->bstart = task_info->last_time;
			info->bend = ginfo->view_end_time;
			info->bcolor = hash_cpu(task_info->last_cpu);
		}
		for (cpu = 0; cpu < ginfo->cpus; cpu++) {
			free_record(task_info->last_records[cpu]);
			task_info->last_records[cpu] = NULL;
		}
		return 0;
	}

	match = try_param(ginfo, rtt_info, record, info)      ||
		try_release(ginfo, rtt_info, record, info)    ||
		try_completion(ginfo, rtt_info, record, info) ||
		try_block(ginfo, rtt_info, record, info)      ||
		try_resume(ginfo, rtt_info, record, info)     ||
		try_other(ginfo, rtt_info, record, info);

	/* This record is neither on our CPU nor related to us, useless */
	if (!match && record->cpu != task_info->last_cpu) {
		if (!task_info->last_records[record->cpu]) {
			task_info->last_records[record->cpu] = record;
			tracecmd_record_ref(record);
		}
		return 0;
	}

	if (!match) {
		cpu = record->cpu;
		/* We need some record, use this if none exist */
		if (!task_info->last_records[cpu]) {
			free_record(task_info->last_records[cpu]);
			task_info->last_records[cpu] = record;
		}

		/* We were on a CPU, now scheduled out */
		if (task_info->last_cpu >= 0) {
			info->box = TRUE;
			info->bcolor = hash_cpu(task_info->last_cpu);
			info->bstart = task_info->last_time;
			info->bend = record->ts;
			task_info->last_cpu = -1;
		}
	} else {
		update_last_task_record(ginfo, task_info, record);
	}
 out:
	return 1;
}

void rt_task_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
			unsigned long long time)
{
	struct rt_task_info *rtt_info = plot->private;

	task_plot_start(ginfo, plot, time);

	rtt_info->wcet = 0ULL;
	rtt_info->period = 0ULL;
	rtt_info->block_time = 0ULL;
	rtt_info->last_job = -1;
	rtt_info->params_found = FALSE;
	update_job(rtt_info, 0);
}

void rt_task_plot_destroy(struct graph_info *ginfo, struct graph_plot *plot)
{
	struct rt_task_info *rtt_info = plot->private;
	free(rtt_info->label);
	task_plot_destroy(ginfo, plot);
}

static const struct plot_callbacks rt_task_cb = {
	.plot_event		= rt_task_plot_event,
	.start			= rt_task_plot_start,
	.destroy		= rt_task_plot_destroy,

	.match_time		= task_plot_match_time,
	.display_last_event	= task_plot_display_last_event,
	.find_record		= task_plot_find_record,
	.display_info		= task_plot_display_info,
};

void rt_plot_task_update_callback(gboolean accept,
				  gint *selected,
				  gint *non_select,
				  gpointer data)
{
	graph_tasks_update_callback(TASK_PLOT_RT, rt_plot_task,
				    accept, selected, non_select, data);
}

void rt_plot_task_plotted(struct graph_info *ginfo, gint **plotted)
{
	graph_tasks_plotted(ginfo, TASK_PLOT_RT, plotted);
}

void rt_plot_task(struct graph_info *ginfo, int pid, int pos)
{
	struct rt_graph_info *rtinfo = &ginfo->rtinfo;
	struct rt_task_info *rtt_info;
	struct graph_plot *plot;
	const char *comm;
	char *label;
	int len;

	if (!find_task_list(rtinfo->tasks, pid))
		die("Cannot create RT plot of non-RT task %d!\n", pid);

	rtt_info = malloc_or_die(sizeof(*rtt_info));
	rtt_info->label = malloc_or_die(LLABEL);

	init_task_plot_info(ginfo, &rtt_info->base, TASK_PLOT_RT, pid);

	comm = pevent_data_comm_from_pid(ginfo->pevent, pid);
	len = strlen(comm) + 100;
	label = malloc_or_die(len);
	snprintf(label, len, "*%s-%d", comm, pid);

	plot = trace_graph_plot_insert(ginfo, pos, label, PLOT_TYPE_TASK,
				       &rt_task_cb, rtt_info);
	free(label);

	trace_graph_plot_add_all_recs(ginfo, plot);
}

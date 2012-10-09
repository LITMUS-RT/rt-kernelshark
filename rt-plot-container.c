#include <stdio.h>
#include <string.h>
#include "trace-graph.h"
#include "trace-hash.h"
#include "trace-filter.h"

int rt_plot_get_containers(struct graph_info *ginfo, gint **conts,
			    gboolean plotted_only)
{
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	struct cont_list *cont;
	int i, count = 0;

	*conts = NULL;
	for (i = 0; i < CONT_HASH_SIZE; i++) {
		for (cont = rtg_info->containers[i]; cont; cont = cont->next) {
			if (!plotted_only || cont->plotted) {
				trace_array_add(conts, &count, cont->cid);
			}
		}
	}
	return count;
}

struct record *
rt_read_next_data(struct graph_info *ginfo, struct tracecmd_input *handle, int *rec_cpu)
{
	unsigned long long ts;
	struct record *record;
	int next;
	int cpu;

	if (rec_cpu)
		*rec_cpu = -1;

	next = -1;
	ts = 0;

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		record = tracecmd_peek_data(handle, cpu);
		if (record && (!ts || get_rts(ginfo, record) < ts)) {
			ts = get_rts(ginfo, record);
			next = cpu;
		}
	}

	if (next >= 0) {
		if (rec_cpu)
			*rec_cpu = next;
		return tracecmd_read_data(handle, next);
	}

	return NULL;
}

struct server_iter_args {
	unsigned long long goal;
	int match_sid;

	int *out_job;
	int *out_tid;
	int *out_tjob;
	int is_running;
};

static inline void try_job_update(struct server_iter_args *args, int candidate)
{
	if (!(*args->out_job))
		(*args->out_job) = candidate;
}

static int server_iterator(struct graph_info *ginfo, struct record *record, void *data)
{
	int sid, job, tid, tjob, match, ret;
	struct server_iter_args *args = data;
	unsigned long long when, time = get_rts(ginfo, record);

	if (time > args->goal + max_rt_search(ginfo))
		return 0;
	if (time < args->goal)
		return 1;

#define ARGS ginfo, record, &sid, &job, &tid, &tjob, &when
	match = rt_graph_check_server_switch_away(ARGS);
	if (match && sid == args->match_sid) {
		/* We were running something */
		(*args->out_tid)  = tid;
		(*args->out_tjob) = tjob;
		try_job_update(args, job);
		args->is_running = 1;
		ret = 0;

	} else if (match && tid == args->match_sid) {
		/* We are being run by someone */
		try_job_update(args, tjob);
	}

	match = rt_graph_check_server_switch_to(ARGS);
	if (match && sid == args->match_sid) {
		/* We must not have been running anything */
		try_job_update(args, job);
		return 0;
	} else if (match && tid == args->match_sid) {
		/* We are being run by someone */
		try_job_update(args, tjob);
	}

#undef  ARGS
	return 1;
}

int get_server_info(struct graph_info *ginfo, struct rt_plot_common *rt,
		    int match_sid, unsigned long long time,
		    int *out_job, int *out_tid, int *out_tjob,
		    struct record **out_record)
{
	struct server_iter_args args = {time, match_sid,
					out_job, out_tid, out_tjob, 0};

	*out_record = find_rt_record(ginfo, rt, time);
	if (!*out_record)
		return 0;

	*out_tjob = *out_job = *out_tid = 0;

	set_cpus_to_rts(ginfo, time);
	iterate(ginfo, 0, server_iterator, &args);

	return args.is_running;
}

void rt_plot_container(struct graph_info *ginfo, int cid)
{
	struct cont_list *cont;
	struct vcpu_list *vlist;
	struct rt_graph_info *rtg_info = &ginfo->rtg_info;
	int key;

	key  = get_container_key(cid);
	cont = find_container(rtg_info->containers, cid, key);
	if (!cont)
		die("Cannot create plot of non-existent container %d!\n", cid);
	if (!cont->vcpus)
		die("Cannot plot container %d with no vcpus!\n", cid);

	cont->plotted = TRUE;

	for (vlist = cont->vcpus; vlist; vlist = vlist->next)
		insert_vcpu(ginfo, cont, vlist);
}

void rt_plot_add_all_containers(struct graph_info *ginfo)
{
	struct cont_list *cont, **conts;
	int i;

	conts = ginfo->rtg_info.containers;
	for (i = 0; i < CONT_HASH_SIZE; i++) {
		for (cont = *conts; cont; cont = cont->next) {
			rt_plot_container(ginfo, cont->cid);
		}
	}
}

struct cont_filter_helper {
	gboolean	all_conts;
	GtkWidget 	**buttons;
	int		*conts;
	gboolean        *selected;
	int		num_conts;
};

#define ALL_CONTS_STR "All Containers"
#define DIALOG_WIDTH	400
#define DIALOG_HEIGHT	600

static void cont_toggle(gpointer data, GtkWidget *widget)
{
	struct cont_filter_helper *helper = data;
	const gchar *label;
	gboolean active;
	int cont;

	label = gtk_button_get_label(GTK_BUTTON(widget));
	active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));

	if (strcmp(label, ALL_CONTS_STR) == 0) {
		helper->all_conts = active;
		if (active) {
			for (cont = 0; cont < helper->num_conts; cont++) {
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(helper->buttons[cont]),
							     TRUE);
			}
		}
	}

	for (cont = 0; cont < helper->num_conts; cont++) {
		if (helper->buttons[cont] == widget) {
			helper->selected[cont] = active;
		}
	}
}



static void do_container_filter(struct graph_info *ginfo,
				struct cont_filter_helper *helper, gpointer data)
{
	struct graph_plot *plot;
	struct vcpu_info *vcpu;
	struct cont_list *cont;
	int i, c, *append;

	append = malloc_or_die(helper->num_conts * sizeof(gint));
	for (i = 0; i < helper->num_conts; i++)
		append[i] = helper->selected[i];

	for (i = ginfo->plots - 1; i >= 0; i--) {
		plot = ginfo->plot_array[i];

		if (plot->type != PLOT_TYPE_SERVER_TASK &&
		    plot->type != PLOT_TYPE_SERVER_CPU)
			continue;

		vcpu = plot->private;
		cont = vcpu->cont;

		for (c = 0; c < helper->num_conts; c++) {
			if (helper->conts[c] == cont->cid)
				break;
		}
		if (c > helper->num_conts)
			continue;

		if (helper->selected[c]) {
			append[c] = FALSE;
		} else {
			cont->plotted = FALSE;
			trace_graph_plot_remove(ginfo, plot);
		}
	}

	/* Add new plots */
	for (c = 0; c < helper->num_conts; c++) {
		if (append[c])
			rt_plot_container(ginfo, helper->conts[c]);
	}
	trace_graph_refresh(ginfo);
}

void trace_container_dialog(struct graph_info *ginfo,
			    gpointer data)
{
	GtkWidget *dialog, *scrollwin, *viewport, *hbox, *vbox, *check, *twidget;
	GtkRequisition req;
	struct tracecmd_input *handle;
	struct pevent *pevent;
	struct cont_filter_helper *cont_helper;
	struct cont_list *cont;
	gchar label[100];
	gint *selected, *conts;
	gboolean tbool;
	int i, result, cont_num, height, width, cont_count, select_count;
	int start, min_cont, tint;

	handle = ginfo->handle;
	if (!handle)
		return;
	pevent = tracecmd_get_pevent(handle);
	if (!pevent)
		return;

	select_count = rt_plot_get_containers(ginfo, &selected, TRUE);
	free(selected);
	cont_count = rt_plot_get_containers(ginfo, &conts, FALSE);

	/* Create helper */
	cont_helper = g_new0(typeof(*cont_helper), 1);
	cont_helper->num_conts = cont_count;
	cont_helper->buttons = g_new0(GtkWidget*, cont_count + 1);
	cont_helper->conts = conts;
	cont_helper->selected = g_new0(gint, cont_count);

	/* Create dialog window */
	dialog = gtk_dialog_new_with_buttons("Select Containers", NULL,
					     GTK_DIALOG_MODAL, "Apply",
					     GTK_RESPONSE_ACCEPT,
					     GTK_STOCK_CANCEL,
					     GTK_RESPONSE_REJECT, NULL);
	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	viewport = gtk_viewport_new(NULL, NULL);
	gtk_widget_show(viewport);

	/* Create scroll area */
	gtk_container_add(GTK_CONTAINER(scrollwin), viewport);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), scrollwin, TRUE, TRUE, 0);
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(viewport), hbox);
	gtk_widget_show(hbox);

	vbox = gtk_vbox_new(TRUE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), vbox, TRUE, FALSE, 0);
	gtk_widget_show(vbox);

	/* Create all container button */
	check = gtk_check_button_new_with_label(ALL_CONTS_STR);
	gtk_box_pack_start(GTK_BOX(vbox), check, TRUE, TRUE, 0);
	cont_helper->buttons[cont_count] = check;
	if (select_count == cont_count)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), TRUE);
	gtk_widget_show(check);
	g_signal_connect_swapped (check, "toggled",
				  G_CALLBACK (cont_toggle),
				  (gpointer) cont_helper);

	/* Create per-container buttons */
	cont_num = 0;
	for (i = 0; i < CONT_HASH_SIZE; i++) {
		for (cont = ginfo->rtg_info.containers[i]; cont; cont = cont->next) {
			g_snprintf(label, 200, "%s-%d", cont->name, cont->cid);
			check = gtk_check_button_new_with_label(label);
			cont_helper->buttons[cont_num] = check;
			cont_helper->conts[cont_num] = cont->cid;
			cont_helper->selected[cont_num] = cont->plotted;

			cont_num++;
		}
	}

	for (start = 0; start < cont_count - 1; start++) {
		min_cont = start;
		for (i = start + 1; i < cont_count; i++) {
			if (cont_helper->conts[i] < cont_helper->conts[min_cont])
				min_cont = i;
		}
		if (min_cont != start) {
			twidget = cont_helper->buttons[min_cont];
			tint = cont_helper->conts[min_cont];
			tbool = cont_helper->selected[min_cont];

			cont_helper->buttons[min_cont] = cont_helper->buttons[start];
			cont_helper->conts[min_cont] = cont_helper->conts[start];
			cont_helper->selected[min_cont] = cont_helper->selected[start];
			cont_helper->buttons[start] = twidget;
			cont_helper->conts[start] = tint;
			cont_helper->selected[start] = tbool;
		}
	}
	for (i = 0; i < cont_count; i++) {
		check = cont_helper->buttons[i];
		gtk_box_pack_start(GTK_BOX(vbox), check, TRUE, FALSE, 0);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), cont_helper->selected[i]);
		gtk_widget_show(check);
		g_signal_connect_swapped (check, "toggled",
					  G_CALLBACK (cont_toggle),
					  (gpointer) cont_helper);

	}


	/* Size */
	gtk_widget_size_request(hbox, &req);
	height = req.height;
	gtk_widget_size_request(scrollwin, &req);
	height += req.height;
	gtk_widget_size_request(dialog, &req);
	width = req.width;
	height += req.height;
	if (width > DIALOG_WIDTH)
		width = DIALOG_WIDTH;
	if (height > DIALOG_HEIGHT)
		height = DIALOG_HEIGHT;
	gtk_widget_set_size_request(GTK_WIDGET(dialog),
				    width, height);
	gtk_widget_show_all(dialog);

	/* Run dialog */
	result = gtk_dialog_run(GTK_DIALOG(dialog));
	if  (result == GTK_RESPONSE_ACCEPT)
		do_container_filter(ginfo, cont_helper, data);

	gtk_widget_destroy(dialog);
	g_free(cont_helper->conts);
	g_free(cont_helper->buttons);
	g_free(cont_helper->selected);
	g_free(cont_helper);
}

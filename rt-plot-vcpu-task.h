struct vcpu_info {
	int			sid;
	int			run_tid;
	unsigned long long	run_time;
	gboolean		fresh;
	char			*label;

	struct cont_list	*cont;
};

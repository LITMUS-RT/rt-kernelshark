# trace-cmd version
TC_VERSION = 1
TC_PATCHLEVEL = 2
TC_EXTRAVERSION = 0

# Kernel Shark version
KS_VERSION = 0
KS_PATCHLEVEL = 2
KS_EXTRAVERSION =

# file format version
FILE_VERSION = 6

MAKEFLAGS += --no-print-directory

# Makefiles suck: This macro sets a default value of $(2) for the
# variable named by $(1), unless the variable has been set by
# environment or command line. This is necessary for CC and AR
# because make sets default values, so the simpler ?= approach
# won't work as expected.
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

# Allow setting CC and AR, or setting CROSS_COMPILE as a prefix.
$(call allow-override,CC,$(CROSS_COMPILE)gcc)
$(call allow-override,AR,$(CROSS_COMPILE)ar)

EXT = -std=gnu99
INSTALL = install

# Use DESTDIR for installing into a different root directory.
# This is useful for building a package. The program will be
# installed in this directory as if it was the root directory.
# Then the build tool can move it later.
DESTDIR ?=
DESTDIR_SQ = '$(subst ','\'',$(DESTDIR))'

prefix ?= /usr/local
bindir_relative = bin
bindir = $(prefix)/$(bindir_relative)
man_dir = $(prefix)/share/man
man_dir_SQ = '$(subst ','\'',$(man_dir))'
html_install = $(prefix)/share/kernelshark/html
html_install_SQ = '$(subst ','\'',$(html_install))'
img_install = $(prefix)/share/kernelshark/html/images
img_install_SQ = '$(subst ','\'',$(img_install))'

export man_dir man_dir_SQ html_install html_install_SQ INSTALL
export img_install img_install_SQ
export DESTDIR DESTDIR_SQ

ifeq ($(prefix),$(HOME))
plugin_dir = $(HOME)/.trace-cmd/plugins
python_dir = $(HOME)/.trace-cmd/python
else
plugin_dir = $(prefix)/share/trace-cmd/plugins
python_dir = $(prefix)/share/trace-cmd/python
PLUGIN_DIR = -DPLUGIN_DIR="$(plugin_dir)"
PYTHON_DIR = -DPYTHON_DIR="$(python_dir)"
PLUGIN_DIR_SQ = '$(subst ','\'',$(PLUGIN_DIR))'
PYTHON_DIR_SQ = '$(subst ','\'',$(PYTHON_DIR))'
endif

HELP_DIR = -DHELP_DIR=$(html_install)
HELP_DIR_SQ = '$(subst ','\'',$(HELP_DIR))'

# copy a bit from Linux kbuild

ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif

PYTHON		:= ctracecmd.so
PYTHON_GUI	:= ctracecmd.so ctracecmdgui.so

# Can build python?
ifeq ($(shell sh -c "python-config --includes > /dev/null 2>&1 && echo y"), y)
	PYTHON_PLUGINS := plugin_python.so
	BUILD_PYTHON := $(PYTHON) $(PYTHON_PLUGINS)
	PYTHON_SO_INSTALL := ctracecmd.install
	PYTHON_PY_INSTALL := event-viewer.install tracecmd.install tracecmdgui.install
endif

# $(call test-build, snippet, ret) -> ret if snippet compiles
#                                  -> empty otherwise
test-build = $(if $(shell sh -c 'echo "$(1)" | \
	$(CC) -o /dev/null -c -x c - > /dev/null 2>&1 && echo y'), $2)

# have udis86 disassembler library?
udis86-flags := $(call test-build,\#include <udis86.h>,-DHAVE_UDIS86 -ludis86)

define BLK_TC_FLUSH_SOURCE
#include <linux/blktrace_api.h>
int main(void) { return BLK_TC_FLUSH; }
endef

# have flush/fua block layer instead of barriers?
blk-flags := $(call test-build,$(BLK_TC_FLUSH_SOURCE),-DHAVE_BLK_TC_FLUSH)

ifeq ("$(origin O)", "command line")
  BUILD_OUTPUT := $(O)
endif

ifeq ($(BUILD_SRC),)
ifneq ($(BUILD_OUTPUT),)

define build_output
	$(if $(VERBOSE:1=),@)$(MAKE) -C $(BUILD_OUTPUT) 	\
	BUILD_SRC=$(CURDIR) -f $(CURDIR)/Makefile $1
endef

saved-output := $(BUILD_OUTPUT)
BUILD_OUTPUT := $(shell cd $(BUILD_OUTPUT) && /bin/pwd)
$(if $(BUILD_OUTPUT),, \
     $(error output directory "$(saved-output)" does not exist))

all: sub-make

gui: force
	$(call build_output, all_cmd)
	$(call build_output, BUILDGUI=1 all_gui)

$(filter-out gui,$(MAKECMDGOALS)): sub-make

sub-make: force
	$(call build_output, $(MAKECMDGOALS))


# Leave processing to above invocation of make
skip-makefile := 1

endif # BUILD_OUTPUT
endif # BUILD_SRC

# We process the rest of the Makefile if this is the final invocation of make
ifeq ($(skip-makefile),)

srctree		:= $(if $(BUILD_SRC),$(BUILD_SRC),$(CURDIR))
objtree		:= $(CURDIR)
src		:= $(srctree)
obj		:= $(objtree)

export prefix bindir src obj

# Shell quotes
bindir_SQ = $(subst ','\'',$(bindir))
bindir_relative_SQ = $(subst ','\'',$(bindir_relative))
plugin_dir_SQ = $(subst ','\'',$(plugin_dir))
python_dir_SQ = $(subst ','\'',$(python_dir))

LIBS = -L. -ltracecmd -ldl
LIB_FILE = libtracecmd.a

PACKAGES= gtk+-2.0 libxml-2.0 gthread-2.0

ifndef BUILDGUI
 BUILDGUI = 0
endif

ifeq ($(BUILDGUI), 1)

CONFIG_INCLUDES = $(shell pkg-config --cflags $(PACKAGES)) -I$(obj)

CONFIG_FLAGS = -DBUILDGUI \
	-DGTK_VERSION=$(shell pkg-config --modversion gtk+-2.0 | \
	awk 'BEGIN{FS="."}{ a = ($$1 * (2^16)) + $$2 * (2^8) + $$3; printf ("%d", a);}')

CONFIG_LIBS = $(shell pkg-config --libs $(PACKAGES))

VERSION		= $(KS_VERSION)
PATCHLEVEL	= $(KS_PATCHLEVEL)
EXTRAVERSION	= $(KS_EXTRAVERSION)

GUI		= 'GUI '
GOBJ		= $@
GSPACE		=

REBUILD_GUI	= /bin/true
G		=
N 		= @/bin/true ||

CONFIG_FLAGS	+= $(HELP_DIR_SQ)
else

CONFIG_INCLUDES = 
CONFIG_LIBS	=
CONFIG_FLAGS	=

VERSION		= $(TC_VERSION)
PATCHLEVEL	= $(TC_PATCHLEVEL)
EXTRAVERSION	= $(TC_EXTRAVERSION)

GUI		=
GSPACE		= "    "
GOBJ		= $(GSPACE)$@

REBUILD_GUI	= $(MAKE) -f $(src)/Makefile BUILDGUI=1 $@
G		= $(REBUILD_GUI); /bin/true ||
N		=
endif

export Q VERBOSE

TRACECMD_VERSION = $(TC_VERSION).$(TC_PATCHLEVEL).$(TC_EXTRAVERSION)
KERNELSHARK_VERSION = $(KS_VERSION).$(KS_PATCHLEVEL).$(KS_EXTRAVERSION)

INCLUDES = -I. $(CONFIG_INCLUDES)

include features.mk

# Set compile option CFLAGS if not set elsewhere
CFLAGS ?= -g -Wall -pg
LDFLAGS ?= -pg

ifndef NO_PTRACE
ifneq ($(call try-cc,$(SOURCE_PTRACE),),y)
	NO_PTRACE = 1
	CFLAGS += -DWARN_NO_PTRACE
endif
endif

ifdef NO_PTRACE
CFLAGS += -DNO_PTRACE
endif

# Append required CFLAGS
override CFLAGS += $(CONFIG_FLAGS) $(INCLUDES) $(PLUGIN_DIR_SQ)
override CFLAGS += $(udis86-flags) $(blk-flags)

ifeq ($(VERBOSE),1)
  Q =
  print_compile =
  print_app_build =
  print_fpic_compile =
  print_shared_lib_compile =
  print_plugin_obj_compile =
  print_plugin_build =
  print_install =
else
  Q = @
  print_compile =		echo '  $(GUI)COMPILE            '$(GOBJ);
  print_app_build =		echo '  $(GUI)BUILD              '$(GOBJ);
  print_fpic_compile =		echo '  $(GUI)COMPILE FPIC       '$(GOBJ);
  print_shared_lib_compile =	echo '  $(GUI)COMPILE SHARED LIB '$(GOBJ);
  print_plugin_obj_compile =	echo '  $(GUI)COMPILE PLUGIN OBJ '$(GOBJ);
  print_plugin_build =		echo '  $(GUI)BUILD PLUGIN       '$(GOBJ);
  print_static_lib_build =	echo '  $(GUI)BUILD STATIC LIB   '$(GOBJ);
  print_install =		echo '  $(GUI)INSTALL     '$(GSPACE)$1'	to	$(DESTDIR_SQ)$2';
endif

do_fpic_compile =					\
	($(print_fpic_compile)				\
	$(CC) -c $(CFLAGS) $(EXT) -fPIC $< -o $@)

do_app_build =						\
	($(print_app_build)				\
	$(CC) $^ -rdynamic -o $@ $(LDFLAGS) $(CONFIG_LIBS) $(LIBS))

do_compile_shared_library =			\
	($(print_shared_lib_compile)		\
	$(CC) --shared $^ -o $@)

do_compile_plugin_obj =				\
	($(print_plugin_obj_compile)		\
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<)

do_plugin_build =				\
	($(print_plugin_build)			\
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -nostartfiles -o $@ $<)

do_build_static_lib =				\
	($(print_static_lib_build)		\
	$(RM) $@;  $(AR) rcs $@ $^)


define check_gui
	if [ $(BUILDGUI) -ne 1 -a ! -z "$(filter $(gui_objs),$(@))" ];	then	\
		$(REBUILD_GUI);							\
	else									\
		$(print_compile)						\
		$(CC) -c $(CFLAGS) $(EXT) $< -o $(obj)/$@;			\
	fi;
endef

$(obj)/%.o: $(src)/%.c
	$(Q)$(call check_gui)

%.o: $(src)/%.c
	$(Q)$(call check_gui)

TRACE_GUI_OBJS = trace-filter.o trace-compat.o trace-hash.o trace-dialog.o \
		trace-xml.o
TRACE_CMD_OBJS = trace-cmd.o trace-record.o trace-read.o trace-split.o trace-listen.o \
	 trace-stack.o trace-options.o
TRACE_VIEW_OBJS = trace-view.o trace-view-store.o
RT_GRAPH_OBJS = rt-graph.o rt-plot-task.o rt-plot-cpu.o rt-plot-container.o rt-plot.o \
	rt-plot-vcpu.o rt-plot-vtask.o
TRACE_GRAPH_OBJS = trace-graph.o trace-plot.o \
	trace-plot-cpu.o trace-plot-task.o \
	$(RT_GRAPH_OBJS) task-list.o
TRACE_VIEW_MAIN_OBJS = trace-view-main.o $(TRACE_VIEW_OBJS) $(TRACE_GUI_OBJS)
TRACE_GRAPH_MAIN_OBJS = trace-graph-main.o $(TRACE_GRAPH_OBJS) $(TRACE_GUI_OBJS)
KERNEL_SHARK_OBJS = $(TRACE_VIEW_OBJS) $(TRACE_GRAPH_OBJS) $(TRACE_GUI_OBJS) \
	trace-capture.o kernel-shark.o

PEVENT_LIB_OBJS = parse-events.o trace-seq.o parse-filter.o parse-utils.o
TCMD_LIB_OBJS = $(PEVENT_LIB_OBJS) trace-util.o trace-input.o trace-ftrace.o \
			trace-output.o trace-recorder.o trace-restore.o trace-usage.o \
			trace-blk-hack.o

PLUGIN_OBJS = plugin_hrtimer.o plugin_kmem.o plugin_sched_switch.o \
	plugin_mac80211.o plugin_jbd2.o plugin_function.o plugin_kvm.o \
	plugin_blk.o

PLUGINS := $(PLUGIN_OBJS:.o=.so)

ALL_OBJS = $(TRACE_CMD_OBJS) $(KERNEL_SHARK_OBJS) $(TRACE_VIEW_MAIN_OBJS) \
	$(TRACE_GRAPH_MAIN_OBJS) $(TCMD_LIB_OBJS) $(PLUGIN_OBJS)

CMD_TARGETS = trace_plugin_dir trace_python_dir tc_version.h libparsevent.a $(LIB_FILE) \
	trace-cmd  $(PLUGINS) $(BUILD_PYTHON)

GUI_TARGETS = ks_version.h trace-graph trace-view kernelshark

TARGETS = $(CMD_TARGETS) $(GUI_TARGETS)


#	cpp $(INCLUDES)

###
#    Default we just build trace-cmd
#
#    If you want kernelshark, then do:  make gui
###

all: all_cmd doc show_gui_make

all_cmd: $(CMD_TARGETS)

gui: $(CMD_TARGETS)
	$(Q)$(MAKE) -f $(src)/Makefile BUILDGUI=1 all_gui

all_gui: $(GUI_TARGETS) show_gui_done

GUI_OBJS = $(KERNEL_SHARK_OBJS) $(TRACE_VIEW_MAIN_OBJS) $(TRACE_GRAPH_MAIN_OBJS)

gui_objs := $(sort $(GUI_OBJS))

trace-cmd: $(TRACE_CMD_OBJS)
	$(Q)$(do_app_build)

kernelshark: $(KERNEL_SHARK_OBJS)
	$(Q)$(G)$(do_app_build)

trace-view: $(TRACE_VIEW_MAIN_OBJS)
	$(Q)$(G)$(do_app_build)

trace-graph: $(TRACE_GRAPH_MAIN_OBJS)
	$(Q)$(G)$(do_app_build)

trace-cmd: libtracecmd.a
kernelshark: libtracecmd.a
trace-view: libtracecmd.a
trace-graph: libtracecmd.a

libparsevent.so: $(PEVENT_LIB_OBJS)
	$(Q)$(do_compile_shared_library)

libparsevent.a: $(PEVENT_LIB_OBJS)
	$(Q)$(do_build_static_lib)

$(TCMD_LIB_OBJS): %.o: $(src)/%.c
	$(Q)$(do_fpic_compile)

libtracecmd.so: $(TCMD_LIB_OBJS)
	$(Q)$(do_compile_shared_library)

libtracecmd.a: $(TCMD_LIB_OBJS)
	$(Q)$(do_build_static_lib)

trace-util.o: trace_plugin_dir

$(PLUGIN_OBJS): %.o : $(src)/%.c
	$(Q)$(do_compile_plugin_obj)

$(PLUGINS): %.so: %.o
	$(Q)$(do_plugin_build)

define make_version.h
	(echo '/* This file is automatically generated. Do not modify. */';		\
	echo \#define VERSION_CODE $(shell						\
	expr $(VERSION) \* 256 + $(PATCHLEVEL));					\
	echo '#define EXTRAVERSION ' $(EXTRAVERSION);					\
	echo '#define VERSION_STRING "'$(VERSION).$(PATCHLEVEL).$(EXTRAVERSION)'"';	\
	echo '#define FILE_VERSION '$(FILE_VERSION);					\
	) > $1
endef

define update_version.h
	($(call make_version.h, $@.tmp);		\
	if [ -r $@ ] && cmp -s $@ $@.tmp; then		\
		rm -f $@.tmp;				\
	else						\
		echo '  UPDATE                 $@';	\
		mv -f $@.tmp $@;			\
	fi);
endef

ks_version.h: force
	$(Q)$(G)$(call update_version.h)

tc_version.h: force
	$(Q)$(N)$(call update_version.h)

define update_dir
	(echo $1 > $@.tmp;	\
	if [ -r $@ ] && cmp -s $@ $@.tmp; then		\
		rm -f $@.tmp;				\
	else						\
		echo '  UPDATE                 $@';	\
		mv -f $@.tmp $@;			\
	fi);
endef

trace_plugin_dir: force
	$(Q)$(N)$(call update_dir, 'PLUGIN_DIR=$(PLUGIN_DIR)')

trace_python_dir: force
	$(Q)$(N)$(call update_dir, 'PYTHON_DIR=$(PYTHON_DIR)')

## make deps

all_objs := $(sort $(ALL_OBJS))
all_deps := $(all_objs:%.o=.%.d)
gui_deps := $(gui_objs:%.o=.%.d)
non_gui_deps = $(filter-out $(gui_deps),$(all_deps))

define check_gui_deps
	if [ ! -z "$(filter $(gui_deps),$(@))" ];	then	\
		if [ $(BUILDGUI) -ne 1 ]; then			\
			$(REBUILD_GUI);				\
		else						\
			$(CC) -M $(CFLAGS) $< > $@;		\
		fi						\
	elif [ $(BUILDGUI) -eq 0 ]; then			\
		$(CC) -M $(CFLAGS) $< > $@;			\
	else							\
		echo SKIPPING $@;				\
	fi;
endef

$(gui_deps): ks_version.h
$(non_gui_deps): tc_version.h

$(all_deps): .%.d: $(src)/%.c
	$(Q)$(call check_gui_deps)

$(all_objs) : %.o : .%.d

ifeq ($(BUILDGUI), 1)
dep_includes := $(wildcard $(gui_deps))
else
dep_includes := $(wildcard $(non_gui_deps))
endif

ifneq ($(dep_includes),)
 include $(dep_includes)
endif

show_gui_make:
	@echo "Note: to build the gui, type \"make gui\""

show_gui_done:
	@echo "gui build complete"

PHONY += show_gui_make

tags:	force
	$(RM) tags
	find . -name '*.[ch]' | xargs ctags --extra=+f --c-kinds=+px

TAGS:	force
	$(RM) TAGS
	find . -name '*.[ch]' | xargs etags

PLUGINS_INSTALL = $(subst .so,.install,$(PLUGINS)) $(subst .so,.install,$(PYTHON_PLUGINS))

define do_install
	$(print_install)				\
	if [ ! -d '$(DESTDIR_SQ)$2' ]; then		\
		$(INSTALL) -d -m 755 '$(DESTDIR_SQ)$2';	\
	fi;						\
	$(INSTALL) $1 '$(DESTDIR_SQ)$2'
endef

$(PLUGINS_INSTALL): %.install : %.so force
	$(Q)$(call do_install,$<,$(plugin_dir_SQ))

install_plugins: $(PLUGINS_INSTALL)

$(PYTHON_SO_INSTALL): %.install : %.so force
	$(Q)$(call do_install,$<,$(python_dir_SQ))

$(PYTHON_PY_INSTALL): %.install : %.py force
	$(Q)$(call do_install,$<,$(python_dir_SQ))

install_python: $(PYTHON_SO_INSTALL) $(PYTHON_PY_INSTALL)

install_cmd: all_cmd install_plugins install_python
	$(Q)$(call do_install,trace-cmd,$(bindir_SQ))

install: install_cmd install_doc
	@echo "Note: to install the gui, type \"make install_gui\""

install_gui: install_cmd gui
	$(Q)$(call do_install,trace-view,$(bindir_SQ))
	$(Q)$(call do_install,trace-graph,$(bindir_SQ))
	$(Q)$(call do_install,kernelshark,$(bindir_SQ))

doc:
	$(MAKE) -C $(src)/Documentation all

doc_clean:
	$(MAKE) -C $(src)/Documentation clean

install_doc:
	$(MAKE) -C $(src)/Documentation install

clean:
	$(RM) *.o *~ $(TARGETS) *.a *.so ctracecmd_wrap.c .*.d
	$(RM) tags TAGS


##### PYTHON STUFF #####

PYTHON_INCLUDES = `python-config --includes`
PYTHON_LDFLAGS = `python-config --ldflags` \
		$(shell python -c "import distutils.sysconfig; print distutils.sysconfig.get_config_var('LINKFORSHARED')")
PYGTK_CFLAGS = `pkg-config --cflags pygtk-2.0`

ctracecmd.so: $(TCMD_LIB_OBJS) ctracecmd.i
	swig -Wall -python -noproxy ctracecmd.i
	gcc -fpic -c $(PYTHON_INCLUDES)  ctracecmd_wrap.c
	$(CC) --shared $(TCMD_LIB_OBJS) ctracecmd_wrap.o -o ctracecmd.so

ctracecmdgui.so: $(TRACE_VIEW_OBJS) $(LIB_FILE)
	swig -Wall -python -noproxy ctracecmdgui.i
	gcc -fpic -c  $(CFLAGS) $(INCLUDES) $(PYTHON_INCLUDES) $(PYGTK_CFLAGS) ctracecmdgui_wrap.c
	$(CC) --shared $^ $(LIBS) $(CONFIG_LIBS) ctracecmdgui_wrap.o -o ctracecmdgui.so

PHONY += python
python: $(PYTHON)

PHONY += python-gui
python-gui: $(PYTHON_GUI)

PHONY += python-plugin
python-plugin: $(PYTHON_PLUGINS)

CFLAGS_plugin_python.o += $(PYTHON_DIR_SQ)

do_compile_python_plugin_obj =			\
	($(print_plugin_obj_compile)		\
	$(CC) -c $(CFLAGS) $(CFLAGS_$@) $(PYTHON_INCLUDES) -fPIC -o $@ $<)

do_python_plugin_build =			\
	($(print_plugin_build)			\
	$(CC) -shared $(PYTHON_LDFLAGS) -o $@ $<)

plugin_python.o: %.o : $(src)/%.c trace_python_dir
	$(Q)$(do_compile_python_plugin_obj)

plugin_python.so: %.so: %.o
	$(Q)$(do_python_plugin_build)

endif # skip-makefile

PHONY += force
force:

# Declare the contents of the .PHONY variable as phony.  We keep that
# information in a variable so we can use it in if_changed and friends.
.PHONY: $(PHONY)

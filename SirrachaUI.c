/*
 * Filename: SirrachaUI.c
 *
 * Copyright (c) 2026 compiledkernel-idk
 * All Rights Reserved.
 *
 * This software is proprietary and confidential.
 * Unauthorized copying, distribution, or use of this file,
 * via any medium, is strictly prohibited.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <gtk/gtk.h>
#include <gtksourceview/gtksource.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define IPC_READY_PATH "/dev/shm/sirracha_ready"
#define IPC_EXEC_PATH "/dev/shm/sirracha_exec.txt"
#define IPC_OUT_PATH "/dev/shm/sirracha_output.txt"
#define IPC_LIB_PATH "/dev/shm/sirracha.so"

static GtkWidget *window;
static GtkSourceView *source_view;
static GtkTextView *console_view;
static GtkLabel *status_label;
static GtkButton *attach_btn;
static GtkButton *exec_btn;
static GtkListStore *script_store;
static pid_t target_pid = -1;
static GHashTable *injected_pids = NULL;

const char *CSS =
    "* { font-family: 'Courier', 'Courier New', monospace; }"
    "window { background-color: #000000; color: #ffffff; }"
    "headerbar { background: #ffffff; color: #000000; border: 3px outset "
    "#ffffff; border-bottom: 3px solid #000000; padding: 4px; }"
    "box, paned, notebook { background-color: #000000; }"
    "textview { background-color: #000000; color: #00ff00; font-family: "
    "'Courier', monospace; font-size: 12px; border: 3px inset #808080; "
    "padding: 8px; }"
    "textview selection { background-color: #ffffff; color: #000000; }"
    "scrolledwindow { border: 3px inset #808080; background-color: #000000; }"
    "treeview { background-color: #000000; color: #ffffff; border-right: 3px "
    "solid #ffffff; font-family: 'Courier', monospace; }"
    "treeview:selected { background-color: #ffffff; color: #000000; }"
    "treeview:hover { background-color: #333333; }"
    "button { background: #c0c0c0; color: #000000; border: 2px outset #ffffff; "
    "padding: 2px 8px; margin: 2px; font-weight: bold; font-size: 10px; "
    "min-height: 20px; }"
    "button:hover { background: #d0d0d0; }"
    "button:active { background: #a0a0a0; border: 2px inset #808080; }"
    "button.suggested-action { background: #ffffff; color: #000000; border: "
    "3px outset #ffffff; }"
    "separator { background-color: #ffffff; min-height: 3px; }"
    "notebook { border: 3px solid #ffffff; background-color: #000000; }"
    "notebook > header { background: #c0c0c0; border-bottom: 3px solid "
    "#000000; padding: 2px; }"
    "notebook > header > tabs > tab { background: #808080; color: #000000; "
    "border: 2px outset #c0c0c0; padding: 4px 12px; margin: 1px; font-weight: "
    "bold; font-size: 10px; }"
    "notebook > header > tabs > tab:hover { background: #a0a0a0; }"
    "notebook > header > tabs > tab:checked { background: #c0c0c0; border: 2px "
    "inset #808080; color: #000000; }"
    "entry { background-color: #ffffff; color: #000000; border: 3px inset "
    "#808080; padding: 4px; font-family: 'Courier', monospace; }"
    "entry:focus { border-color: #000000; }"
    "switch { background-color: #808080; border: 3px inset #808080; }"
    "switch:checked { background-color: #ffffff; }"
    ".console { font-size: 11px; color: #00ff00; background-color: #000000; "
    "border-top: 3px solid #ffffff; padding: 8px; font-family: 'Courier', "
    "monospace; }";

static void log_console(const char *msg) {
  GtkTextBuffer *buf = gtk_text_view_get_buffer(console_view);
  GtkTextIter end;
  gtk_text_buffer_get_end_iter(buf, &end);

  char *fmt = g_strdup_printf(
      "[%s] %s\n",
      g_time_val_to_iso8601(&(GTimeVal){g_get_real_time() / 1000000, 0}) + 11,
      msg);
  fmt[9] = ']';
  fmt[10] = ' ';

  gtk_text_buffer_insert(buf, &end, fmt, -1);
  g_free(fmt);

  GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(
      GTK_SCROLLED_WINDOW(gtk_widget_get_parent(GTK_WIDGET(console_view))));
  gtk_adjustment_set_value(adj, gtk_adjustment_get_upper(adj));
}

static void set_status(const char *status) {
  gtk_label_set_text(status_label, status);
}

static void refresh_scripts(void) {
  if (!script_store)
    return;
  gtk_list_store_clear(script_store);
  DIR *d = opendir("scripts");
  if (!d) {
    mkdir("scripts", 0755);
    d = opendir("scripts");
  }
  if (d) {
    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
      if (dir->d_name[0] != '.' &&
          (strstr(dir->d_name, ".lua") || strstr(dir->d_name, ".txt"))) {
        GtkTreeIter iter;
        gtk_list_store_append(script_store, &iter);
        gtk_list_store_set(script_store, &iter, 0, "text-x-script", 1,
                           dir->d_name, -1);
      }
    }
    closedir(d);
  }
}

static void on_script_selected(GtkTreeView *tree, GtkTreePath *path,
                               GtkTreeViewColumn *col, gpointer data) {
  (void)col;
  (void)data;
  GtkTreeModel *model = gtk_tree_view_get_model(tree);
  GtkTreeIter iter;
  if (gtk_tree_model_get_iter(model, &iter, path)) {
    char *name;
    gtk_tree_model_get(model, &iter, 1, &name, -1);
    char *full_path = g_strdup_printf("scripts/%s", name);
    char *content;
    gsize len;
    if (g_file_get_contents(full_path, &content, &len, NULL)) {
      GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(source_view));
      gtk_text_buffer_set_text(buf, content, len);
      g_free(content);
      log_console(g_strdup_printf("Loaded %s", name));
    }
    g_free(full_path);
    g_free(name);
  }
}

static int send_script(const char *script) {
  unlink(IPC_OUT_PATH);
  FILE *f = fopen(IPC_EXEC_PATH, "w");
  if (!f)
    return -1;
  fprintf(f, "%s", script);
  fclose(f);
  chmod(IPC_EXEC_PATH, 0666);

  // Also copy to container's /tmp if we have a target PID
  if (target_pid > 0) {
    char *container_exec_path =
        g_strdup_printf("/proc/%d/root/tmp/sirracha_exec.txt", target_pid);
    FILE *cf = fopen(container_exec_path, "w");
    if (cf) {
      fprintf(cf, "%s", script);
      fclose(cf);
      chmod(container_exec_path, 0666);
    }
    g_free(container_exec_path);
  }

  for (int i = 0; i < 100; i++) { // 10s timeout
    // Check container output first
    if (target_pid > 0) {
      char *container_out_path =
          g_strdup_printf("/proc/%d/root/tmp/sirracha_output.txt", target_pid);
      if (access(container_out_path, F_OK) == 0) {
        g_usleep(50000);
        char *out;
        if (g_file_get_contents(container_out_path, &out, NULL, NULL)) {
          log_console(out);
          g_free(out);
          unlink(container_out_path);
          g_free(container_out_path);
          return 0;
        }
      }
      g_free(container_out_path);
    }

    // Check host output (fallback)
    if (access(IPC_OUT_PATH, F_OK) == 0) {
      g_usleep(50000);
      char *out;
      if (g_file_get_contents(IPC_OUT_PATH, &out, NULL, NULL)) {
        log_console(out);
        g_free(out);
        unlink(IPC_OUT_PATH);
        return 0;
      }
    }
    g_usleep(100000);
  }
  log_console("Execution timed out");
  return -1;
}

static void save_response_cb(GtkDialog *dlg, int response, gpointer data) {
  (void)data;
  if (response == GTK_RESPONSE_ACCEPT) {
    GtkFileChooser *chooser = GTK_FILE_CHOOSER(dlg);
    GFile *file = gtk_file_chooser_get_file(chooser);
    char *filename = g_file_get_path(file);

    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(source_view));
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buf, &start, &end);
    char *text = gtk_text_buffer_get_text(buf, &start, &end, FALSE);

    g_file_set_contents(filename, text, -1, NULL);
    g_free(text);
    g_free(filename);
    g_object_unref(file);
  }
  gtk_window_destroy(GTK_WINDOW(dlg));
}

static void open_response_cb(GtkDialog *dlg, int response, gpointer data) {
  (void)data;
  if (response == GTK_RESPONSE_ACCEPT) {
    GtkFileChooser *chooser = GTK_FILE_CHOOSER(dlg);
    GFile *file = gtk_file_chooser_get_file(chooser);
    char *filename = g_file_get_path(file);

    char *contents;
    if (g_file_get_contents(filename, &contents, NULL, NULL)) {
      GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(source_view));
      gtk_text_buffer_set_text(buf, contents, -1);
      g_free(contents);
    }
    g_free(filename);
    g_object_unref(file);
  }
  gtk_window_destroy(GTK_WINDOW(dlg));
}

static void on_save(GtkButton *b, gpointer d) {
  (void)b;
  (void)d;
  GtkWidget *dialog = gtk_file_chooser_dialog_new(
      "Save Script", GTK_WINDOW(window), GTK_FILE_CHOOSER_ACTION_SAVE, "Cancel",
      GTK_RESPONSE_CANCEL, "Save", GTK_RESPONSE_ACCEPT, NULL);
  gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "script.lua");
  gtk_widget_show(dialog);
  g_signal_connect(dialog, "response", G_CALLBACK(save_response_cb), NULL);
}

static void on_open(GtkButton *b, gpointer d) {
  (void)b;
  (void)d;
  GtkWidget *dialog = gtk_file_chooser_dialog_new(
      "Open Script", GTK_WINDOW(window), GTK_FILE_CHOOSER_ACTION_OPEN, "Cancel",
      GTK_RESPONSE_CANCEL, "Open", GTK_RESPONSE_ACCEPT, NULL);
  gtk_widget_show(dialog);
  g_signal_connect(dialog, "response", G_CALLBACK(open_response_cb), NULL);
}

static void on_exec(GtkButton *b, gpointer d) {
  (void)b;
  (void)d;
  if (target_pid < 0) {
    log_console("Not attached");
    return;
  }
  GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(source_view));
  GtkTextIter start, end;
  gtk_text_buffer_get_bounds(buf, &start, &end);
  char *code = gtk_text_buffer_get_text(buf, &start, &end, FALSE);
  if (code && strlen(code) > 0) {
    log_console("Executing...");
    send_script(code);
  }
  g_free(code);
}

static gboolean check_lib(pid_t pid) {
  char path[64];
  snprintf(path, 64, "/proc/%d/maps", pid);
  char *content;
  if (g_file_get_contents(path, &content, NULL, NULL)) {
    gboolean found = strstr(content, "sirracha") != NULL;
    g_free(content);
    return found;
  }
  return FALSE;
}

static pid_t find_sober_pid(void) {
  DIR *proc = opendir("/proc");
  struct dirent *e;
  pid_t pid = -1;
  while ((e = readdir(proc))) {
    if (atoi(e->d_name) > 0) {
      char p[64];
      snprintf(p, 64, "/proc/%s/comm", e->d_name);
      char *n;
      if (g_file_get_contents(p, &n, NULL, NULL)) {
        if (strstr(n, "sober"))
          pid = atoi(e->d_name);
        g_free(n);
      }
    }
  }
  closedir(proc);
  return pid;
}

static void log_async(const char *msg) {
  g_idle_add((GSourceFunc)log_console, g_strdup(msg));
}

static void attach_thread(GTask *task, gpointer s, gpointer d,
                          GCancellable *c) {
  (void)task;
  (void)s;
  (void)d;
  (void)c;

  unlink(IPC_READY_PATH);

  pid_t pid = find_sober_pid();
  if (pid < 0) {
    log_async("Sober not found. Launching...");
    system("flatpak run org.vinegarhq.Sober >/dev/null 2>&1 &");
    for (int i = 0; i < 10; i++) {
      sleep(1);
      pid = find_sober_pid();
      if (pid > 0)
        break;
    }
  }

  if (pid > 0) {
    char *log_path =
        g_strdup_printf("/dev/shm/sirracha_inject_%d.log", getpid());
    char *cmd =
        g_strdup_printf("./inject_sober.sh %d > %s 2>&1", pid, log_path);
    system("cp -f sober_test_inject.so /dev/shm/sirracha.so");

    log_async("Injecting...");
    int ret = system(cmd);

    char *log_content;
    if (g_file_get_contents(log_path, &log_content, NULL, NULL)) {
      log_async(log_content);
      g_free(log_content);
    }
    unlink(log_path);
    g_free(log_path);
    g_free(cmd);

    if (ret != 0) {
      log_async("Injector script failed.");
    }

    log_async("Waiting for Ready Signal...");
    for (int i = 0; i < 30; i++) {
      // Check container path via /proc (primary method for Flatpak)
      char *container_ready_path =
          g_strdup_printf("/proc/%d/root/dev/shm/sirracha_ready", pid);
      if (access(container_ready_path, F_OK) == 0) {
        target_pid = pid;
        g_idle_add((GSourceFunc)set_status, "Attached");
        g_idle_add((GSourceFunc)gtk_widget_set_sensitive, exec_btn);
        log_async("Ready Signal Received!");
        g_free(container_ready_path);
        return;
      }
      g_free(container_ready_path);

      // Fallback: check host path (for non-containerized processes)
      if (access(IPC_READY_PATH, F_OK) == 0) {
        target_pid = pid;
        g_idle_add((GSourceFunc)set_status, "Attached");
        g_idle_add((GSourceFunc)gtk_widget_set_sensitive, exec_btn);
        log_async("Ready Signal Received (host)!");
        return;
      }

      sleep(1);
    }

    if (check_lib(pid)) {
      log_async("Library loaded but no signal (Scanner stuck?)");
      target_pid = pid; // Assume semi-success
      g_idle_add((GSourceFunc)set_status, "Attached (No Signal)");
      g_idle_add((GSourceFunc)gtk_widget_set_sensitive, exec_btn);
      return;
    }
  } else {
    log_async("Could not find/launch Sober.");
  }
  g_idle_add((GSourceFunc)set_status, "Attach Failed");
}

static void on_attach(GtkButton *b, gpointer d) {
  (void)b;
  (void)d;
  set_status("Attaching...");
  GTask *t = g_task_new(NULL, NULL, NULL, NULL);
  g_task_run_in_thread(t, attach_thread);
  g_object_unref(t);
}

static void activate(GtkApplication *app, gpointer d) {
  (void)d;
  GtkCssProvider *css = gtk_css_provider_new();
  gtk_css_provider_load_from_string(css, CSS);
  gtk_style_context_add_provider_for_display(
      gdk_display_get_default(), GTK_STYLE_PROVIDER(css),
      GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

  window = gtk_application_window_new(app);
  gtk_window_set_default_size(GTK_WINDOW(window), 1000, 700);
  gtk_window_set_icon_name(GTK_WINDOW(window), "application-x-executable");

  GtkWidget *header = gtk_header_bar_new();
  gtk_header_bar_set_show_title_buttons(GTK_HEADER_BAR(header), TRUE);
  gtk_window_set_titlebar(GTK_WINDOW(window), header);

  attach_btn = GTK_BUTTON(gtk_button_new_with_label("Attach"));
  g_signal_connect(attach_btn, "clicked", G_CALLBACK(on_attach), NULL);
  gtk_header_bar_pack_start(GTK_HEADER_BAR(header), GTK_WIDGET(attach_btn));

  status_label = GTK_LABEL(gtk_label_new("Ready"));
  gtk_header_bar_pack_start(GTK_HEADER_BAR(header), GTK_WIDGET(status_label));

  exec_btn = GTK_BUTTON(gtk_button_new_with_label("Execute"));
  gtk_widget_add_css_class(GTK_WIDGET(exec_btn), "suggested-action");
  g_signal_connect(exec_btn, "clicked", G_CALLBACK(on_exec), NULL);
  gtk_header_bar_pack_end(GTK_HEADER_BAR(header), GTK_WIDGET(exec_btn));

  GtkButton *clear = GTK_BUTTON(gtk_button_new_with_label("Clear"));
  g_signal_connect(clear, "clicked", G_CALLBACK(on_script_selected), NULL);
  gtk_header_bar_pack_end(GTK_HEADER_BAR(header), GTK_WIDGET(clear));

  GtkButton *save_btn = GTK_BUTTON(gtk_button_new_with_label("Save"));
  g_signal_connect(save_btn, "clicked", G_CALLBACK(on_save), NULL);
  gtk_header_bar_pack_end(GTK_HEADER_BAR(header), GTK_WIDGET(save_btn));

  GtkButton *open_btn = GTK_BUTTON(gtk_button_new_with_label("Open"));
  g_signal_connect(open_btn, "clicked", G_CALLBACK(on_open), NULL);
  gtk_header_bar_pack_end(GTK_HEADER_BAR(header), GTK_WIDGET(open_btn));

  GtkWidget *hpaned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
  gtk_paned_set_position(GTK_PANED(hpaned), 200);
  gtk_window_set_child(GTK_WINDOW(window), hpaned);

  // Sidebar
  GtkWidget *sw1 = gtk_scrolled_window_new();
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw1), GTK_POLICY_NEVER,
                                 GTK_POLICY_AUTOMATIC);
  script_store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);
  GtkWidget *tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(script_store));
  gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(tree), FALSE);
  GtkCellRenderer *rend = gtk_cell_renderer_text_new();
  GtkTreeViewColumn *col =
      gtk_tree_view_column_new_with_attributes("Script", rend, "text", 1, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col);
  g_signal_connect(tree, "row-activated", G_CALLBACK(on_script_selected), NULL);
  gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sw1), tree);
  gtk_paned_set_start_child(GTK_PANED(hpaned), sw1);

  GtkWidget *notebook = gtk_notebook_new();
  gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook), GTK_POS_TOP);
  gtk_paned_set_end_child(GTK_PANED(hpaned), notebook);

  GtkWidget *vpaned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
  gtk_paned_set_position(GTK_PANED(vpaned), 500);

  GtkWidget *sw2 = gtk_scrolled_window_new();
  GtkSourceLanguageManager *lm = gtk_source_language_manager_get_default();
  GtkSourceBuffer *buf = gtk_source_buffer_new(NULL);
  gtk_source_buffer_set_language(
      buf, gtk_source_language_manager_get_language(lm, "lua"));
  source_view = GTK_SOURCE_VIEW(gtk_source_view_new_with_buffer(buf));
  gtk_source_view_set_show_line_numbers(source_view, TRUE);
  gtk_source_view_set_auto_indent(source_view, TRUE);

  GtkSourceStyleSchemeManager *sm =
      gtk_source_style_scheme_manager_get_default();
  GtkSourceStyleScheme *scheme =
      gtk_source_style_scheme_manager_get_scheme(sm, "oblivion");
  if (scheme)
    gtk_source_buffer_set_style_scheme(buf, scheme);

  GtkSourceCompletion *comp = gtk_source_view_get_completion(source_view);
  GtkSourceCompletionWords *words = gtk_source_completion_words_new("Lua");
  gtk_source_completion_words_register(words, GTK_TEXT_BUFFER(buf));
  gtk_source_completion_add_provider(comp,
                                     GTK_SOURCE_COMPLETION_PROVIDER(words));

  gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sw2),
                                GTK_WIDGET(source_view));
  gtk_paned_set_start_child(GTK_PANED(vpaned), sw2);

  GtkWidget *sw3 = gtk_scrolled_window_new();
  console_view = GTK_TEXT_VIEW(gtk_text_view_new());
  gtk_widget_add_css_class(GTK_WIDGET(console_view), "console");
  gtk_text_view_set_editable(console_view, FALSE);
  gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sw3),
                                GTK_WIDGET(console_view));
  gtk_paned_set_end_child(GTK_PANED(vpaned), sw3);

  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), vpaned,
                           gtk_label_new("Editor"));

  GtkWidget *settings_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
  gtk_widget_set_margin_start(settings_box, 20);
  gtk_widget_set_margin_end(settings_box, 20);
  gtk_widget_set_margin_top(settings_box, 20);
  gtk_widget_set_margin_bottom(settings_box, 20);

  GtkWidget *settings_title = gtk_label_new(NULL);
  gtk_label_set_markup(GTK_LABEL(settings_title),
                       "<span size='x-large' weight='bold'>Settings</span>");
  gtk_widget_set_halign(settings_title, GTK_ALIGN_START);
  gtk_box_append(GTK_BOX(settings_box), settings_title);

  GtkWidget *auto_attach_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
  GtkWidget *auto_attach_label = gtk_label_new("Auto-attach on startup");
  gtk_widget_set_hexpand(auto_attach_label, TRUE);
  gtk_widget_set_halign(auto_attach_label, GTK_ALIGN_START);
  GtkWidget *auto_attach_switch = gtk_switch_new();
  gtk_box_append(GTK_BOX(auto_attach_box), auto_attach_label);
  gtk_box_append(GTK_BOX(auto_attach_box), auto_attach_switch);
  gtk_box_append(GTK_BOX(settings_box), auto_attach_box);

  GtkWidget *topmost_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
  GtkWidget *topmost_label = gtk_label_new("Keep window on top");
  gtk_widget_set_hexpand(topmost_label, TRUE);
  gtk_widget_set_halign(topmost_label, GTK_ALIGN_START);
  GtkWidget *topmost_switch = gtk_switch_new();
  gtk_box_append(GTK_BOX(topmost_box), topmost_label);
  gtk_box_append(GTK_BOX(topmost_box), topmost_switch);
  gtk_box_append(GTK_BOX(settings_box), topmost_box);

  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), settings_box,
                           gtk_label_new("Settings"));

  GtkWidget *about_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);
  gtk_widget_set_margin_start(about_box, 40);
  gtk_widget_set_margin_end(about_box, 40);
  gtk_widget_set_margin_top(about_box, 40);
  gtk_widget_set_margin_bottom(about_box, 40);
  gtk_widget_set_valign(about_box, GTK_ALIGN_CENTER);

  GtkWidget *logo = gtk_image_new_from_file("sriracha_logo.svg");
  gtk_image_set_pixel_size(GTK_IMAGE(logo), 128);
  gtk_box_append(GTK_BOX(about_box), logo);

  GtkWidget *about_title = gtk_label_new(NULL);
  gtk_label_set_markup(
      GTK_LABEL(about_title),
      "<span size='xx-large' weight='bold'>Sirracha Executor</span>");
  gtk_box_append(GTK_BOX(about_box), about_title);

  GtkWidget *about_version = gtk_label_new("Version PRE_RELEASE");
  gtk_box_append(GTK_BOX(about_box), about_version);

  GtkWidget *about_desc =
      gtk_label_new("Lua script executor for Roblox on Linux");
  gtk_label_set_justify(GTK_LABEL(about_desc), GTK_JUSTIFY_CENTER);
  gtk_box_append(GTK_BOX(about_box), about_desc);

  GtkWidget *about_author = gtk_label_new(NULL);
  gtk_label_set_markup(GTK_LABEL(about_author),
                       "<span size='small'>© 2026 compiledkernel-idk</span>");
  gtk_box_append(GTK_BOX(about_box), about_author);

  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), about_box,
                           gtk_label_new("About"));

  refresh_scripts();
  gtk_window_present(GTK_WINDOW(window));
}

int main(int argc, char **argv) {
  GtkApplication *app =
      gtk_application_new("com.sirracha.ui", G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
  return g_application_run(G_APPLICATION(app), argc, argv);
}

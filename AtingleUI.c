#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
// #include <sys/ptrace.h>
// #include <sys/wait.h_
// #include <sys/uio.h>
// #include <sys/mman.h>
// #include <dlfcn.h>
// #include <sys/user.h>
// #include <errno.h>
// #include <limits.h>
// #include <fcntl.h>
#include <pthread.h>
#include <glib.h>

static GtkWidget *main_window;
static GtkWidget *editor;

pid_t findPID(const char *target_name) {
    DIR* d = opendir("/proc");
    if (!d) {
        g_printerr("Error: Could not open /proc directory.\n");
        return -1;
    }

    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR) continue;

        pid_t pid = atoi(e->d_name);
        if (pid <= 0) continue;

        char exe_path[PATH_MAX];
        char link_target[PATH_MAX];
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

        ssize_t len = readlink(exe_path, link_target, sizeof(link_target) - 1);
        if (len == -1) continue;
        link_target[len] = '\0';

        if (strstr(link_target, target_name)) {
            closedir(d);
            return pid;
        }
    }
    closedir(d);
    g_printerr("Error: Process with name containing '%s' not found.\n", target_name);
    return -1;
}

char* load_file_to_string(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    rewind(f);
    char *buffer = malloc(length + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    fread(buffer, 1, length, f);
    buffer[length] = '\0';
    fclose(f);
    return buffer;
}

static void on_execute_clicked(GtkButton *button, gpointer user_data) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor));
    GtkTextIter start, end;
    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);
    gchar *text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
    g_print("Execute clicked. Script content:\n%s\n", text);
    g_free(text);
}

static void on_clear_clicked(GtkButton *button, gpointer user_data) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor));
    gtk_text_buffer_set_text(buffer, "", -1);
}

static void open_file_response(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source_object);
    GFile *file = gtk_file_dialog_open_finish(dialog, res, NULL);
    if (file) {
        char *filename = g_file_get_path(file);
        if (filename) {
            char *content = load_file_to_string(filename);
            if (content) {
                GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor));
                gtk_text_buffer_set_text(buffer, content, -1);
                free(content);
            }
            g_free(filename);
        }
        g_object_unref(file);
    }
}

static void on_open_file_clicked(GtkButton *button, gpointer user_data) {
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Open Script");
    gtk_file_dialog_open(dialog, GTK_WINDOW(main_window), NULL, open_file_response, NULL);
}

static void save_file_response(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source_object);
    GFile *file = gtk_file_dialog_save_finish(dialog, res, NULL);
    if (file) {
        char *filename = g_file_get_path(file);
        if (filename) {
            GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor));
            GtkTextIter start, end;
            gtk_text_buffer_get_start_iter(buffer, &start);
            gtk_text_buffer_get_end_iter(buffer, &end);
            gchar *text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
            FILE *f = fopen(filename, "w");
            if (f) {
                fwrite(text, 1, strlen(text), f);
                fclose(f);
            }
            g_free(text);
            g_free(filename);
        }
        g_object_unref(file);
    }
}

static void on_save_file_clicked(GtkButton *button, gpointer user_data) {
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Save Script");
    gtk_file_dialog_save(dialog, GTK_WINDOW(main_window), NULL, save_file_response, NULL);
}

struct attach_data {
    GtkButton *button;
};

struct label_update_data {
    GtkButton *button;
    char *new_label;
};

static gboolean update_button_label(gpointer user_data) {
    struct label_update_data *data = user_data;
    gtk_button_set_label(data->button, data->new_label);
    g_free(data->new_label);
    g_free(data);
    return G_SOURCE_REMOVE;
}

static void* attach_thread_func(void *arg) {
    struct attach_data *data = arg;
    const char* so_path = "./sober_test_inject.so";
    const char* injector_path = "./injector";

    pid_t pid = findPID("sober");
    if (pid == -1) {
        struct label_update_data *upd = g_new(struct label_update_data, 1);
        upd->button = data->button;
        upd->new_label = g_strdup("Attach (Not Found)");
        g_idle_add(update_button_label, upd);
        g_free(data);
        return NULL;
    }

    g_print("Attempting to run injector for PID %d with library %s\n", pid, so_path);

    gchar *stdout_buf = NULL;
    gchar *stderr_buf = NULL;
    gint exit_status = 0;
    GError *error = NULL;

    gchar *pid_str = g_strdup_printf("%d", pid);
    gchar *argv[] = { (gchar*)injector_path, pid_str, (gchar*)so_path, NULL };

    gboolean success = g_spawn_sync(
        NULL,
        argv,
        NULL,
        G_SPAWN_SEARCH_PATH,
        NULL, NULL,
        &stdout_buf,
        &stderr_buf,
        &exit_status,
        &error
    );

    g_free(pid_str);

    if (error) {
        g_printerr("Error running injector: %s\n", error->message);
        g_error_free(error);
        struct label_update_data *upd = g_new(struct label_update_data, 1);
        upd->button = data->button;
        upd->new_label = g_strdup("Attach (Exec Error)");
        g_idle_add(update_button_label, upd);
        g_free(data);
        return NULL;
    }

    if (!success || exit_status != 0) {
        g_printerr("injector failed. Exit status: %d\n", exit_status);
        if (stdout_buf) g_print("Injector stdout:\n%s\n", stdout_buf);
        if (stderr_buf) g_printerr("Injector stderr:\n%s\n", stderr_buf);
        struct label_update_data *upd = g_new(struct label_update_data, 1);
        upd->button = data->button;
        upd->new_label = g_strdup("Attach (Failed)");
        g_idle_add(update_button_label, upd);
        g_free(data);
        g_free(stdout_buf);
        g_free(stderr_buf);
        return NULL;
    }

    g_print("injector ran successfully.\n");
    if (stdout_buf) g_print("Injector stdout:\n%s\n", stdout_buf);
    if (stderr_buf) g_printerr("Injector stderr:\n%s\n", stderr_buf);

    struct label_update_data *upd = g_new(struct label_update_data, 1);
    upd->button = data->button;
    upd->new_label = g_strdup("Attach (Success)");
    g_idle_add(update_button_label, upd);
    g_free(data);
    g_free(stdout_buf);
    g_free(stderr_buf);
    return NULL;
}

static void on_attach_clicked(GtkButton *button, gpointer user_data) {
    gtk_button_set_label(button, "Attaching...");
    struct attach_data *data = g_malloc(sizeof(struct attach_data));
    data->button = button;
    pthread_t thread;
    pthread_create(&thread, NULL, attach_thread_func, data);
    pthread_detach(thread);
}

static void activate(GtkApplication *app, gpointer user_data) {
    main_window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(main_window), "Atingle");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 800, 350);
    gtk_window_set_resizable(GTK_WINDOW(main_window), FALSE);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
    gtk_window_set_child(GTK_WINDOW(main_window), grid);

    editor = gtk_text_view_new();
    gtk_widget_set_size_request(editor, 660, 270);
    gtk_grid_attach(GTK_GRID(grid), editor, 0, 0, 1, 1);

    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_grid_attach(GTK_GRID(grid), button_box, 0, 1, 1, 1);

    GtkWidget *btn_execute = gtk_button_new_with_label("Execute");
    GtkWidget *btn_clear = gtk_button_new_with_label("Clear");
    GtkWidget *btn_open = gtk_button_new_with_label("Open File");
    GtkWidget *btn_save = gtk_button_new_with_label("Save File");
    GtkWidget *btn_attach = gtk_button_new_with_label("Attach");

    gtk_box_append(GTK_BOX(button_box), btn_execute);
    gtk_box_append(GTK_BOX(button_box), btn_clear);
    gtk_box_append(GTK_BOX(button_box), btn_open);
    gtk_box_append(GTK_BOX(button_box), btn_save);
    gtk_box_append(GTK_BOX(button_box), btn_attach);

    g_signal_connect(btn_execute, "clicked", G_CALLBACK(on_execute_clicked), NULL);
    g_signal_connect(btn_clear, "clicked", G_CALLBACK(on_clear_clicked), NULL);
    g_signal_connect(btn_open, "clicked", G_CALLBACK(on_open_file_clicked), NULL);
    g_signal_connect(btn_save, "clicked", G_CALLBACK(on_save_file_clicked), NULL);
    g_signal_connect(btn_attach, "clicked", G_CALLBACK(on_attach_clicked), NULL);

    gtk_window_present(GTK_WINDOW(main_window));
}

int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("com.atingle.app", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}

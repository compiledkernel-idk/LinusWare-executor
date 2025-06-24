/* 
    UI Functionality removed for now
 */

#include <gtk/gtk.h>
#include <gtksourceview/gtksource.h>

typedef struct {
    GtkWindow     *main_window;
    GtkNotebook   *notebook;
    GtkTextBuffer *output_buffer;
} AppWidgets;

static void on_close_tab_clicked(GtkButton *button, gpointer user_data) {
    GtkNotebook *nb  = GTK_NOTEBOOK(user_data);
    GtkWidget   *pg  = g_object_get_data(G_OBJECT(button), "notebook_page");
    gint         idx = gtk_notebook_page_num(nb, pg);
    if (idx != -1) gtk_notebook_remove_page(nb, idx);
}

static void on_add_custom_tab_clicked(GtkButton *button, gpointer user_data) {
    AppWidgets *w = (AppWidgets*)user_data;
    GtkSourceBuffer *buf = GTK_SOURCE_BUFFER(gtk_source_buffer_new(NULL));
    GtkSourceLanguageManager *lm = gtk_source_language_manager_get_default();
    GtkSourceLanguage *lua_l = gtk_source_language_manager_get_language(lm, "lua");
    if (lua_l) gtk_source_buffer_set_language(buf, lua_l);
    GtkWidget *view    = gtk_source_view_new_with_buffer(buf);
    gtk_source_view_set_show_line_numbers(GTK_SOURCE_VIEW(view), TRUE);
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scrolled), view);
    gint page = gtk_notebook_append_page(w->notebook, scrolled, NULL);
    gtk_notebook_set_tab_reorderable(w->notebook, scrolled, TRUE);
    gtk_notebook_set_current_page(w->notebook, page);
    GtkWidget *tab_box      = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
    GtkWidget *tab_label    = gtk_label_new("Untitled");
    GtkWidget *close_button = gtk_button_new_from_icon_name("window-close", GTK_ICON_SIZE_MENU);
    gtk_button_set_relief(GTK_BUTTON(close_button), GTK_RELIEF_NONE);
    gtk_box_pack_start(GTK_BOX(tab_box), tab_label, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(tab_box), close_button, FALSE, FALSE, 0);
    gtk_widget_show_all(tab_box);

    g_object_set_data(G_OBJECT(close_button), "notebook_page", scrolled);
    g_signal_connect(close_button, "clicked", G_CALLBACK(on_close_tab_clicked), w->notebook);
    gtk_notebook_set_tab_label(w->notebook, scrolled, tab_box);
}
static void activate(GtkApplication *app, gpointer user_data) {
    AppWidgets *w = g_new0(AppWidgets, 1);

    GtkWidget *win = gtk_application_window_new(app);
    w->main_window = GTK_WINDOW(win);
    gtk_window_set_default_size(GTK_WINDOW(win), 1024, 768);
    gtk_window_set_title(GTK_WINDOW(win), "teemsploit");
    GtkWidget *hdr = gtk_header_bar_new();
    gtk_header_bar_set_title(GTK_HEADER_BAR(hdr), "teemsploit");
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hdr), TRUE);
    gtk_window_set_titlebar(GTK_WINDOW(win), hdr);
    GtkWidget *hdr_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hdr), hdr_box);
    GtkWidget *open_btn = gtk_button_new_with_label("Open");
    GtkWidget *save_btn = gtk_button_new_with_label("Save");
    GtkWidget *add_tab = gtk_button_new_with_label("Add Tab");
    g_signal_connect(add_tab, "clicked", G_CALLBACK(on_add_custom_tab_clicked), w);
    gtk_box_pack_start(GTK_BOX(hdr_box), open_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hdr_box), save_btn, FALSE, FALSE, 0);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hdr), add_tab);
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_container_add(GTK_CONTAINER(win), paned);
    GtkWidget *left = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(left, TRUE);
    gtk_widget_set_hexpand(left, TRUE);
    gtk_paned_pack1(GTK_PANED(paned), left, TRUE, FALSE);
    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_vexpand(right, TRUE);
    gtk_widget_set_hexpand(right, TRUE);
    gtk_paned_pack2(GTK_PANED(paned), right, TRUE, FALSE);
    w->notebook = GTK_NOTEBOOK(gtk_notebook_new());
    gtk_notebook_set_scrollable(w->notebook, TRUE);
    gtk_box_pack_start(GTK_BOX(right), GTK_WIDGET(w->notebook), TRUE, TRUE, 0);
    GtkSourceBuffer *def_buf = GTK_SOURCE_BUFFER(gtk_source_buffer_new(NULL));
    GtkSourceLanguage *def_l = gtk_source_language_manager_get_language(
        gtk_source_language_manager_get_default(), "lua");
    if (def_l) gtk_source_buffer_set_language(def_buf, def_l);
    GtkWidget *def_view = gtk_source_view_new_with_buffer(def_buf);
    gtk_source_view_set_show_line_numbers(GTK_SOURCE_VIEW(def_view), TRUE);
    GtkWidget *def_scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(def_scrolled), def_view);
    gtk_notebook_append_page(w->notebook, def_scrolled, gtk_label_new("Script Editor"));
    GtkWidget *out_label = gtk_label_new("Output:");
    gtk_box_pack_start(GTK_BOX(right), out_label, FALSE, FALSE, 2);
    GtkWidget *out_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(out_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(out_view), FALSE);
    w->output_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(out_view));
    GtkWidget *out_scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(out_scrolled, TRUE);
    gtk_container_add(GTK_CONTAINER(out_scrolled), out_view);
    gtk_box_pack_start(GTK_BOX(right), out_scrolled, TRUE, TRUE, 0);
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(right), btn_box, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), gtk_button_new_with_label("Execute"),   FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), gtk_button_new_with_label("Clear Code"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), gtk_button_new_with_label("Clear Output"),FALSE, FALSE, 0);
    gtk_widget_show_all(win);
}

int main(int argc, char **argv) {
    GtkApplication *app = gtk_application_new("com.teemsploit.app", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}

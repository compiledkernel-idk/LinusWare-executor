/*
 * LinusWare Executor - Premium Qt UI
 * Copyright (c) 2026 compiledkernel-idk
 * Proprietary and confidential.
 */

#include <QApplication>
#include <QFile>
#include <QFileDialog>
#include <QFont>
#include <QFontDatabase>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QMessageBox>
#include <QPainter>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollBar>
#include <QShortcut>
#include <QStackedWidget>
#include <QSyntaxHighlighter>
#include <QTabBar>
#include <QTextEdit>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWidget>

class LuauHighlighter : public QSyntaxHighlighter {
public:
  LuauHighlighter(QTextDocument *parent) : QSyntaxHighlighter(parent) {

    keywordFmt.setForeground(QColor("#7C3AED"));
    keywordFmt.setFontWeight(QFont::Bold);

    builtinFmt.setForeground(QColor("#10B981"));

    stringFmt.setForeground(QColor("#FCD34D"));

    numberFmt.setForeground(QColor("#C792EA"));

    commentFmt.setForeground(QColor("#5C6370"));
    commentFmt.setFontItalic(true);

    operatorFmt.setForeground(QColor("#ABB2BF"));

    funcFmt.setForeground(QColor("#82AAFF"));

    keywordPat = QRegularExpression(
        "\\b(and|break|do|else|elseif|end|false|for|function|if|in|local|"
        "nil|not|or|repeat|return|then|true|until|while|continue|type|export)"
        "\\b");
    builtinPat = QRegularExpression(
        "\\b(print|warn|error|game|workspace|script|math|string|table|"
        "pcall|xpcall|tostring|tonumber|require|typeof|setmetatable|"
        "getmetatable|pairs|ipairs|next|select|unpack|rawget|rawset|"
        "Instance|Vector3|CFrame|Color3|UDim2|Enum|task|wait|spawn|delay)\\b");
    stringPat = QRegularExpression("(\"[^\"]*\"|'[^']*'|\\[\\[.*?\\]\\])");
    numberPat = QRegularExpression("\\b\\d+(\\.\\d+)?\\b");
    commentPat = QRegularExpression("--.*$");
    funcPat = QRegularExpression("\\b([a-zA-Z_][a-zA-Z0-9_]*)\\s*\\(");
  }

protected:
  void highlightBlock(const QString &text) override {

    applyPattern(text, funcPat, funcFmt, 1);
    applyPattern(text, builtinPat, builtinFmt);
    applyPattern(text, keywordPat, keywordFmt);
    applyPattern(text, numberPat, numberFmt);
    applyPattern(text, stringPat, stringFmt);
    applyPattern(text, commentPat, commentFmt);
  }

private:
  void applyPattern(const QString &text, const QRegularExpression &pat,
                    const QTextCharFormat &fmt, int group = 0) {
    QRegularExpressionMatchIterator it = pat.globalMatch(text);
    while (it.hasNext()) {
      QRegularExpressionMatch m = it.next();
      setFormat(m.capturedStart(group), m.capturedLength(group), fmt);
    }
  }

  QTextCharFormat keywordFmt, builtinFmt, stringFmt, numberFmt, commentFmt,
      operatorFmt, funcFmt;
  QRegularExpression keywordPat, builtinPat, stringPat, numberPat, commentPat,
      funcPat;
};

class AccentLine : public QFrame {
public:
  AccentLine(QWidget *parent = nullptr) : QFrame(parent) {
    setFixedHeight(2);
    setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
                  "stop:0 #6D28D9, stop:1 #5B21B6);");
  }
};

class NavButton : public QPushButton {
public:
  NavButton(const QString &text, QWidget *parent = nullptr)
      : QPushButton(text, parent), isActive(false) {
    setCursor(Qt::PointingHandCursor);
    setCheckable(true);
    setFixedHeight(40);
    updateStyle();
  }

  void setActive(bool active) {
    isActive = active;
    setChecked(active);
    updateStyle();
  }

private:
  void updateStyle() {
    if (isActive) {
      setStyleSheet(R"(
                QPushButton {
                    background: transparent;
                    color: #7C3AED;
                    border: none;
                    border-left: 3px solid #7C3AED;
                    padding-left: 20px;
                    text-align: left;
                    font-weight: bold;
                    font-size: 13px;
                }
            )");
    } else {
      setStyleSheet(R"(
                QPushButton {
                    background: transparent;
                    color: #6B7280;
                    border: none;
                    border-left: 3px solid transparent;
                    padding-left: 20px;
                    text-align: left;
                    font-size: 13px;
                }
                QPushButton:hover {
                    color: #E5E7EB;
                    border-left: 3px solid #374151;
                }
            )");
    }
  }

  bool isActive;
};

class ActionButton : public QPushButton {
public:
  enum Style { Primary, Secondary, Danger };

  ActionButton(const QString &text, Style style = Secondary,
               QWidget *parent = nullptr)
      : QPushButton(text, parent) {
    setCursor(Qt::PointingHandCursor);
    setFixedHeight(38);

    QString base, hover, pressed;
    switch (style) {
    case Primary:
      base = "background: qlineargradient(x1:0, y1:0, x2:1, y2:1, "
             "stop:0 #7C3AED, stop:1 #6D28D9); color: #fff;";
      hover = "background: qlineargradient(x1:0, y1:0, x2:1, y2:1, "
              "stop:0 #8B5CF6, stop:1 #6B21A8);";
      pressed = "background: #5B21B6;";
      break;
    case Danger:
      base = "background: #DC2626; color: #fff;";
      hover = "background: #EF4444;";
      pressed = "background: #B91C1C;";
      break;
    default:
      base = "background: #1F2937; color: #E5E7EB; border: 1px solid #374151;";
      hover = "background: #374151; border-color: #4B5563;";
      pressed = "background: #4B5563;";
    }

    setStyleSheet(QString(R"(
            QPushButton {
                %1
                border-radius: 8px;
                padding: 0 16px;
                font-weight: 600;
                font-size: 12px;
                letter-spacing: 0.5px;
            }
            QPushButton:hover { %2 }
            QPushButton:pressed { %3 }
            QPushButton:disabled {
                background: #1F2937;
                color: #4B5563;
            }
        )")
                      .arg(base, hover, pressed));
  }
};

class LinusWareWindow : public QMainWindow {
  Q_OBJECT

public:
  LinusWareWindow() {
    setWindowTitle("LINUSWARE EXECUTOR");
    setMinimumSize(1000, 650);
    resize(1100, 720);

    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    QHBoxLayout *mainLayout = new QHBoxLayout(central);
    mainLayout->setSpacing(0);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    QWidget *sidebar = new QWidget();
    sidebar->setFixedWidth(220);
    sidebar->setObjectName("sidebar");
    QVBoxLayout *sideLayout = new QVBoxLayout(sidebar);
    sideLayout->setSpacing(0);
    sideLayout->setContentsMargins(0, 0, 0, 0);

    QWidget *brand = new QWidget();
    brand->setFixedHeight(80);
    QVBoxLayout *brandLayout = new QVBoxLayout(brand);
    brandLayout->setContentsMargins(20, 20, 20, 10);

    QLabel *logo = new QLabel("LINUSWARE");
    logo->setStyleSheet("font-size: 22px; font-weight: 800; color: #7C3AED; "
                        "letter-spacing: 3px;");
    brandLayout->addWidget(logo);

    QLabel *tagline = new QLabel("EXECUTOR ");
    tagline->setStyleSheet(
        "font-size: 10px; color: #4B5563; letter-spacing: 2px;");
    brandLayout->addWidget(tagline);

    sideLayout->addWidget(brand);
    sideLayout->addWidget(new AccentLine());

    QWidget *statusWidget = new QWidget();
    statusWidget->setFixedHeight(50);
    QHBoxLayout *statusLayout = new QHBoxLayout(statusWidget);
    statusLayout->setContentsMargins(20, 10, 20, 10);

    statusDot = new QLabel("•");
    statusDot->setStyleSheet("color: #EF4444; font-size: 10px;");
    statusLayout->addWidget(statusDot);

    statusLabel = new QLabel("Disconnected");
    statusLabel->setStyleSheet("color: #6B7280; font-size: 12px;");
    statusLayout->addWidget(statusLabel);
    statusLayout->addStretch();

    sideLayout->addWidget(statusWidget);

    QLabel *navLabel = new QLabel("  NAVIGATION");
    navLabel->setStyleSheet(
        "color: #374151; font-size: 9px; font-weight: bold; "
        "letter-spacing: 2px; padding: 15px 0 8px 18px;");
    sideLayout->addWidget(navLabel);

    navEditor = new NavButton("Editor");
    navConsole = new NavButton("Console");
    navSettings = new NavButton("Settings");

    navEditor->setActive(true);

    connect(navEditor, &QPushButton::clicked, this,
            [this]() { switchPage(0); });

    connect(navConsole, &QPushButton::clicked, this,
            [this]() { switchPage(1); });
    connect(navSettings, &QPushButton::clicked, this,
            [this]() { switchPage(2); });

    sideLayout->addWidget(navEditor);
    sideLayout->addWidget(navConsole);
    sideLayout->addWidget(navSettings);

    sideLayout->addStretch();

    QLabel *actionsLabel = new QLabel("  QUICK ACTIONS");
    actionsLabel->setStyleSheet(
        "color: #374151; font-size: 9px; font-weight: bold; "
        "letter-spacing: 2px; padding: 15px 0 8px 18px;");
    sideLayout->addWidget(actionsLabel);

    QWidget *actionsWidget = new QWidget();
    QVBoxLayout *actionsLayout = new QVBoxLayout(actionsWidget);
    actionsLayout->setContentsMargins(16, 0, 16, 20);
    actionsLayout->setSpacing(8);

    btnInject = new ActionButton("INJECT", ActionButton::Primary);
    btnExecute = new ActionButton("EXECUTE", ActionButton::Secondary);

    connect(btnInject, &QPushButton::clicked, this, &LinusWareWindow::onInject);
    connect(btnExecute, &QPushButton::clicked, this,
            &LinusWareWindow::onExecute);

    actionsLayout->addWidget(btnInject);
    actionsLayout->addWidget(btnExecute);

    sideLayout->addWidget(actionsWidget);

    mainLayout->addWidget(sidebar);

    QWidget *content = new QWidget();
    content->setObjectName("content");
    QVBoxLayout *contentLayout = new QVBoxLayout(content);
    contentLayout->setSpacing(0);
    contentLayout->setContentsMargins(0, 0, 0, 0);

    pages = new QStackedWidget();

    QWidget *editorPage = new QWidget();
    QVBoxLayout *editorLayout = new QVBoxLayout(editorPage);
    editorLayout->setSpacing(0);
    editorLayout->setContentsMargins(0, 0, 0, 0);

    QWidget *editorToolbar = new QWidget();
    editorToolbar->setFixedHeight(50);
    editorToolbar->setStyleSheet(
        "background: #111827; border-bottom: 1px solid #1F2937;");
    QHBoxLayout *toolbarLayout = new QHBoxLayout(editorToolbar);
    toolbarLayout->setContentsMargins(16, 8, 16, 8);

    QLabel *editorTitle = new QLabel("Code Editor");
    editorTitle->setStyleSheet(
        "color: #E5E7EB; font-size: 14px; font-weight: 600;");
    toolbarLayout->addWidget(editorTitle);

    toolbarLayout->addStretch();

    ActionButton *btnOpen = new ActionButton("Open");
    ActionButton *btnSave = new ActionButton("Save");
    ActionButton *btnClear = new ActionButton("Clear");

    connect(btnOpen, &QPushButton::clicked, this, &LinusWareWindow::onOpen);
    connect(btnSave, &QPushButton::clicked, this, &LinusWareWindow::onSave);
    connect(btnClear, &QPushButton::clicked, this, &LinusWareWindow::onClear);

    toolbarLayout->addWidget(btnOpen);
    toolbarLayout->addWidget(btnSave);
    toolbarLayout->addWidget(btnClear);

    editorLayout->addWidget(editorToolbar);

    editor = new QPlainTextEdit();
    editor->setObjectName("editor");
    editor->setPlainText("-- Welcome to LinusWare Executor!\n"
                         "-- Inject first, then execute your scripts.\n\n"
                         "print(\"Hello from LinusWare!\")\n\n"
                         "-- Example: Speed hack\n"
                         "-- local player = game.Players.LocalPlayer\n"
                         "-- player.Character.Humanoid.WalkSpeed = 100");

    QFont monoFont("Courier New", 10);
    monoFont.setStyleHint(QFont::TypeWriter); monoFont.setWeight(QFont::Bold);
    
    editor->setFont(monoFont);

    highlighter = new LuauHighlighter(editor->document());
    editorLayout->addWidget(editor);

    pages->addWidget(editorPage);

    QWidget *consolePage = new QWidget();
    QVBoxLayout *consolePageLayout = new QVBoxLayout(consolePage);
    consolePageLayout->setSpacing(0);
    consolePageLayout->setContentsMargins(0, 0, 0, 0);

    QWidget *consoleToolbar = new QWidget();
    consoleToolbar->setFixedHeight(50);
    consoleToolbar->setStyleSheet(
        "background: #111827; border-bottom: 1px solid #1F2937;");
    QHBoxLayout *consoleToolbarLayout = new QHBoxLayout(consoleToolbar);
    consoleToolbarLayout->setContentsMargins(16, 8, 16, 8);

    QLabel *consoleTitle = new QLabel("Console Output");
    consoleTitle->setStyleSheet(
        "color: #E5E7EB; font-size: 14px; font-weight: 600;");
    consoleToolbarLayout->addWidget(consoleTitle);
    consoleToolbarLayout->addStretch();

    ActionButton *btnClearConsole = new ActionButton("Clear");
    connect(btnClearConsole, &QPushButton::clicked,
            [this]() { console->clear(); });
    consoleToolbarLayout->addWidget(btnClearConsole);

    consolePageLayout->addWidget(consoleToolbar);

    console = new QTextEdit();
    console->setObjectName("console");
    console->setReadOnly(true);
    console->setFont(monoFont);
    console->append("<span style='color:#10B981;'>[LinusWare]</span> Ready. "
                    "Inject to begin.");
    consolePageLayout->addWidget(console);

    pages->addWidget(consolePage);

    QWidget *settingsPage = new QWidget();
    QVBoxLayout *settingsLayout = new QVBoxLayout(settingsPage);
    settingsLayout->setContentsMargins(20, 20, 20, 20);
    settingsLayout->setSpacing(16);

    QLabel *settingsTitle = new QLabel("Settings");
    settingsTitle->setStyleSheet(
        "color: #E5E7EB; font-size: 18px; font-weight: 700;");
    settingsLayout->addWidget(settingsTitle);

    auto addSetting = [&](const QString &name, const QString &desc,
                          bool checked = false) {
      QWidget *row = new QWidget();
      QHBoxLayout *rowLayout = new QHBoxLayout(row);
      rowLayout->setContentsMargins(0, 8, 0, 8);

      QVBoxLayout *textLayout = new QVBoxLayout();
      QLabel *nameLabel = new QLabel(name);
      nameLabel->setStyleSheet(
          "color: #E5E7EB; font-size: 13px; font-weight: 600;");
      QLabel *descLabel = new QLabel(desc);
      descLabel->setStyleSheet("color: #6B7280; font-size: 11px;");
      textLayout->addWidget(nameLabel);
      textLayout->addWidget(descLabel);

      rowLayout->addLayout(textLayout);
      rowLayout->addStretch();

      QPushButton *toggle = new QPushButton(checked ? "ON" : "OFF");
      toggle->setCheckable(true);
      toggle->setChecked(checked);
      toggle->setFixedSize(50, 28);
      toggle->setStyleSheet(
          checked ? "background: #7C3AED; color: #fff; border-radius: 14px; "
                    "font-weight: bold; font-size: 10px;"
                  : "background: #374151; color: #9CA3AF; border-radius: 14px; "
                    "font-weight: bold; font-size: 10px;");
      connect(toggle, &QPushButton::toggled, [toggle](bool on) {
        toggle->setText(on ? "ON" : "OFF");
        toggle->setStyleSheet(
            on ? "background: #7C3AED; color: #fff; border-radius: 14px; "
                 "font-weight: bold; font-size: 10px;"
               : "background: #374151; color: #9CA3AF; border-radius: 14px; "
                 "font-weight: bold; font-size: 10px;");
      });
      rowLayout->addWidget(toggle);

      settingsLayout->addWidget(row);
    };

    addSetting("Auto-Inject", "Automatically inject when Sober starts", false);
    addSetting("Auto-Execute", "Run script immediately after injection", false);
    addSetting("Top Most", "Keep window above other applications", false);
    addSetting("Save on Close", "Save current script when closing", true);

    QFrame *divider = new QFrame();
    divider->setFrameShape(QFrame::HLine);
    divider->setStyleSheet("color: #1F2937;");
    settingsLayout->addWidget(divider);

    QLabel *aboutTitle = new QLabel("About");
    aboutTitle->setStyleSheet(
        "color: #E5E7EB; font-size: 14px; font-weight: 600; padding-top: 8px;");
    settingsLayout->addWidget(aboutTitle);

    QLabel *aboutText =
        new QLabel("LinusWare Executor \n"
                   "A lightweight Luau executor for Sober on Linux\n\n"
                   "GitHub: github.com/compiledkernel-idk/linusware-executor\n"
                   "Professional Luau executor for Linux");
    aboutText->setStyleSheet(
        "color: #6B7280; font-size: 12px; line-height: 1.6;");
    settingsLayout->addWidget(aboutText);

    settingsLayout->addStretch();

    pages->addWidget(settingsPage);

    contentLayout->addWidget(pages);
    mainLayout->addWidget(content);

    applyStyle();

    statusTimer = new QTimer(this);
    connect(statusTimer, &QTimer::timeout, this, &LinusWareWindow::checkStatus);
    statusTimer->start(2000);

    QShortcut *execShortcut = new QShortcut(QKeySequence("F5"), this);
    connect(execShortcut, &QShortcut::activated, this,
            &LinusWareWindow::onExecute);

    QShortcut *saveShortcut = new QShortcut(QKeySequence::Save, this);
    connect(saveShortcut, &QShortcut::activated, this,
            &LinusWareWindow::onSave);
  }

private slots:
  void switchPage(int index) {
    pages->setCurrentIndex(index);
    navEditor->setActive(index == 0);
    navConsole->setActive(index == 1);
    navSettings->setActive(index == 2);
  }

  void onInject() {
    btnInject->setEnabled(false);
    btnInject->setText("⏳ INJECTING...");
    logConsole("Checking for Sober process...", "#FCD34D");

    QProcess checkProc;
    checkProc.start("pgrep", QStringList() << "-f" << "sober");
    checkProc.waitForFinished(2000);
    QString pgrep_out = checkProc.readAllStandardOutput().trimmed();

    if (pgrep_out.isEmpty()) {
      logConsole("Sober not running, starting...", "#FCD34D");
      QProcess::startDetached("flatpak", QStringList()
                                             << "run" << "org.vinegarhq.Sober");
      logConsole(
          "Waiting for Sober to start. Join a game, then click INJECT again.",
          "#6B7280");
      btnInject->setEnabled(true);
      btnInject->setText("INJECT");
      return;
    }

    QString pid = pgrep_out.split("\n").first();
    logConsole("Found Sober (PID: " + pid + "), injecting...", "#10B981");

    QProcess *proc = new QProcess(this);
    proc->start("./inject_sober.sh", QStringList());
    proc->waitForFinished(15000);

    QString output =
        proc->readAllStandardOutput() + proc->readAllStandardError();

    QFile maps("/proc/" + pid + "/maps");
    bool verified = false;
    if (maps.open(QIODevice::ReadOnly)) {
      QString content = maps.readAll();
      verified = content.contains("linusware");
      maps.close();
    }

    if (verified || output.contains("SUCCESS")) {
      logConsole("✓ Injection successful!", "#10B981");
      statusLabel->setText("Connected");
      statusLabel->setStyleSheet("color: #10B981; font-size: 12px;");
      statusDot->setStyleSheet("color: #10B981; font-size: 10px;");
      injected = true;
    } else {
      logConsole("✗ Injection failed: " + output.left(100), "#EF4444");
    }

    btnInject->setEnabled(true);
    btnInject->setText("INJECT");
  }

  void onExecute() {
    if (!injected) {
      logConsole("Not injected! Click INJECT first.", "#EF4444");
      return;
    }

    QString script = editor->toPlainText();
    if (script.trimmed().isEmpty()) {
      logConsole("Script is empty!", "#EF4444");
      return;
    }

    logConsole("Executing script...", "#FCD34D");

    QFile file("/tmp/linusware_exec.txt");
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
      file.write(script.toUtf8());
      file.close();
    }

    QTimer::singleShot(500, this, [this]() {
      QFile outFile("/tmp/linusware_output.txt");
      if (outFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QString output = outFile.readAll().trimmed();
        if (!output.isEmpty()) {
          logConsole(output, output.startsWith("✓") ? "#10B981" : "#E5E7EB");
        }
        outFile.close();
      }
    });
  }

  void onClear() { editor->clear(); }

  void onOpen() {
    QString fileName = QFileDialog::getOpenFileName(
        this, "Open Script", QDir::homePath(),
        "Lua Scripts (*.lua *.txt);;All Files (*)");
    if (!fileName.isEmpty()) {
      QFile file(fileName);
      if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        editor->setPlainText(file.readAll());
        file.close();
        logConsole("Loaded: " + QFileInfo(fileName).fileName(), "#10B981");
      }
    }
  }

  void onSave() {
    QString fileName = QFileDialog::getSaveFileName(
        this, "Save Script", QDir::homePath() + "/script.lua",
        "Lua Scripts (*.lua);;All Files (*)");
    if (!fileName.isEmpty()) {
      QFile file(fileName);
      if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        file.write(editor->toPlainText().toUtf8());
        file.close();
        logConsole("Saved: " + QFileInfo(fileName).fileName(), "#10B981");
      }
    }
  }

  void checkStatus() {
    QFile ready("/tmp/linusware_ready");
    if (ready.exists() && !injected) {
      statusLabel->setText("Connected");
      statusLabel->setStyleSheet("color: #10B981; font-size: 12px;");
      statusDot->setStyleSheet("color: #10B981; font-size: 10px;");
      injected = true;
    }
  }

private:
  void logConsole(const QString &msg, const QString &color = "#E5E7EB") {
    console->append(
        QString("<span style='color:%1;'>%2</span>").arg(color, msg));

    QScrollBar *sb = console->verticalScrollBar();
    sb->setValue(sb->maximum());
  }

  void applyStyle() {
    setStyleSheet(R"(
            * {
                font-family: 'Courier New', 'Lucida Console', monospace;
            }
            QMainWindow {
                background: #0F172A;
            }
            #sidebar {
                background: #0F172A;
                border-right: 1px solid #1E293B;
            }
            #content {
                background: #0F172A;
            }
            #editor {
                background: #111827;
                color: #E5E7EB;
                border: none;
                padding: 16px;
                selection-background-color: #374151;
                selection-color: #fff;
            }
            #console {
                background: #111827;
                color: #9CA3AF;
                border: none;
                padding: 16px;
            }
            #scriptsList {
                background: #1F2937;
                border: 1px solid #374151;
                border-radius: 8px;
                color: #E5E7EB;
                padding: 8px;
                outline: none;
            }
            #scriptsList::item {
                padding: 12px;
                border-radius: 6px;
                margin: 2px 0;
            }
            #scriptsList::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 rgba(255,107,157,0.3), stop:1 rgba(78,205,196,0.3));
                color: #fff;
            }
            #scriptsList::item:hover {
                background: #374151;
            }
            QScrollBar:vertical {
                background: #1F2937;
                width: 10px;
                border-radius: 5px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: #4B5563;
                border-radius: 5px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background: #6B7280;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
            QScrollBar:horizontal {
                background: #1F2937;
                height: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:horizontal {
                background: #4B5563;
                border-radius: 5px;
                min-width: 30px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #6B7280;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0;
            }
        )");
  }

  QPlainTextEdit *editor;
  QTextEdit *console;
  QLabel *statusLabel;
  QLabel *statusDot;
  QPushButton *btnInject;
  QPushButton *btnExecute;
  NavButton *navEditor;
  NavButton *navConsole;
  NavButton *navSettings;
  QStackedWidget *pages;
  LuauHighlighter *highlighter;
  QTimer *statusTimer;
  bool injected = false;
};

int main(int argc, char *argv[]) {

  qputenv("QT_ENABLE_HIGHDPI_SCALING", "1");

  QApplication app(argc, argv);

  QFontDatabase::addApplicationFont(":/fonts/Inter-Regular.ttf");

  LinusWareWindow window;
  window.show();

  return app.exec();
}



#include "LinusWareQt.moc"

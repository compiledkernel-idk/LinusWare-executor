/*
 * Sirracha Executor - Qt UI
 * Beautiful, lightweight C++ interface
 */

#include <QApplication>
#include <QFile>
#include <QFileDialog>
#include <QFont>
#include <QFontDatabase>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QMainWindow>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QRegularExpression>
#include <QSplitter>
#include <QSyntaxHighlighter>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

// Lua Syntax Highlighter
class LuaSyntaxHighlighter : public QSyntaxHighlighter {
public:
  LuaSyntaxHighlighter(QTextDocument *parent) : QSyntaxHighlighter(parent) {
    // Keywords - red accent
    keywordFormat.setForeground(QColor("#ff5555"));
    keywordFormat.setFontWeight(QFont::Bold);
    QStringList keywords = {"\\band\\b",    "\\bbreak\\b",  "\\bdo\\b",
                            "\\belse\\b",   "\\belseif\\b", "\\bend\\b",
                            "\\bfalse\\b",  "\\bfor\\b",    "\\bfunction\\b",
                            "\\bif\\b",     "\\bin\\b",     "\\blocal\\b",
                            "\\bnil\\b",    "\\bnot\\b",    "\\bor\\b",
                            "\\brepeat\\b", "\\breturn\\b", "\\bthen\\b",
                            "\\btrue\\b",   "\\buntil\\b",  "\\bwhile\\b"};
    for (const QString &pattern : keywords) {
      rules.append({QRegularExpression(pattern), keywordFormat});
    }

    // Built-in functions - green
    builtinFormat.setForeground(QColor("#50fa7b"));
    QStringList builtins = {
        "\\bprint\\b",     "\\bwarn\\b",   "\\berror\\b",  "\\bgame\\b",
        "\\bworkspace\\b", "\\bscript\\b", "\\bmath\\b",   "\\bstring\\b",
        "\\btable\\b",     "\\bpcall\\b",  "\\bxpcall\\b", "\\btostring\\b",
        "\\btonumber\\b",  "\\brequire\\b"};
    for (const QString &pattern : builtins) {
      rules.append({QRegularExpression(pattern), builtinFormat});
    }

    // Strings - yellow
    stringFormat.setForeground(QColor("#f1fa8c"));
    rules.append({QRegularExpression("\"[^\"]*\""), stringFormat});
    rules.append({QRegularExpression("'[^']*'"), stringFormat});

    // Numbers - purple
    numberFormat.setForeground(QColor("#bd93f9"));
    rules.append({QRegularExpression("\\b\\d+(\\.\\d+)?\\b"), numberFormat});

    // Comments - gray
    commentFormat.setForeground(QColor("#6272a4"));
    commentFormat.setFontItalic(true);
    rules.append({QRegularExpression("--[^\n]*"), commentFormat});
  }

protected:
  void highlightBlock(const QString &text) override {
    for (const auto &rule : rules) {
      QRegularExpressionMatchIterator it = rule.pattern.globalMatch(text);
      while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        setFormat(match.capturedStart(), match.capturedLength(), rule.format);
      }
    }
  }

private:
  struct HighlightRule {
    QRegularExpression pattern;
    QTextCharFormat format;
  };
  QVector<HighlightRule> rules;
  QTextCharFormat keywordFormat, builtinFormat, stringFormat, numberFormat,
      commentFormat;
};

// Main Window
class SirrachaWindow : public QMainWindow {
  Q_OBJECT

public:
  SirrachaWindow() {
    setWindowTitle("SIRRACHA v1.0");
    setMinimumSize(900, 600);
    resize(1000, 700);

    // Central widget
    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    QHBoxLayout *mainLayout = new QHBoxLayout(central);
    mainLayout->setSpacing(0);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    // === Left Sidebar ===
    QWidget *sidebar = new QWidget();
    sidebar->setFixedWidth(200);
    sidebar->setObjectName("sidebar");
    QVBoxLayout *sidebarLayout = new QVBoxLayout(sidebar);
    sidebarLayout->setSpacing(8);
    sidebarLayout->setContentsMargins(12, 12, 12, 12);

    // Logo/Title (no emoji)
    QLabel *logo = new QLabel("SIRRACHA");
    logo->setObjectName("logo");
    sidebarLayout->addWidget(logo);

    // Version
    QLabel *version = new QLabel("v1.0");
    version->setObjectName("version");
    sidebarLayout->addWidget(version);

    // Status
    statusLabel = new QLabel("Disconnected");
    statusLabel->setObjectName("status");
    sidebarLayout->addWidget(statusLabel);

    sidebarLayout->addSpacing(20);

    // Buttons (no emojis)
    btnInject = new QPushButton("INJECT");
    btnInject->setObjectName("btnInject");
    btnInject->setCursor(Qt::PointingHandCursor);
    connect(btnInject, &QPushButton::clicked, this, &SirrachaWindow::onInject);
    sidebarLayout->addWidget(btnInject);

    btnExecute = new QPushButton("EXECUTE");
    btnExecute->setObjectName("btnExecute");
    btnExecute->setCursor(Qt::PointingHandCursor);
    connect(btnExecute, &QPushButton::clicked, this,
            &SirrachaWindow::onExecute);
    sidebarLayout->addWidget(btnExecute);

    btnClear = new QPushButton("CLEAR");
    btnClear->setObjectName("btnClear");
    btnClear->setCursor(Qt::PointingHandCursor);
    connect(btnClear, &QPushButton::clicked, this, &SirrachaWindow::onClear);
    sidebarLayout->addWidget(btnClear);

    sidebarLayout->addSpacing(20);

    // Scripts list
    QLabel *scriptsLabel = new QLabel("SCRIPTS");
    scriptsLabel->setObjectName("sectionLabel");
    sidebarLayout->addWidget(scriptsLabel);

    scriptsList = new QListWidget();
    scriptsList->setObjectName("scriptsList");
    scriptsList->addItem("Hello World");
    scriptsList->addItem("Speed Hack");
    scriptsList->addItem("Fly Script");
    connect(scriptsList, &QListWidget::itemClicked, this,
            &SirrachaWindow::onScriptSelected);
    sidebarLayout->addWidget(scriptsList);

    sidebarLayout->addStretch();

    mainLayout->addWidget(sidebar);

    // === Main Content ===
    QWidget *content = new QWidget();
    content->setObjectName("content");
    QVBoxLayout *contentLayout = new QVBoxLayout(content);
    contentLayout->setSpacing(0);
    contentLayout->setContentsMargins(0, 0, 0, 0);

    // Editor header
    QLabel *editorLabel = new QLabel("  EDITOR");
    editorLabel->setObjectName("editorLabel");
    contentLayout->addWidget(editorLabel);

    // Editor
    editor = new QPlainTextEdit();
    editor->setObjectName("editor");
    editor->setPlainText("-- Welcome to Sirracha!\nprint(\"Hello, World!\")");

    // Set monospace font
    QFont font("JetBrains Mono", 11);
    font.setStyleHint(QFont::Monospace);
    editor->setFont(font);

    // Syntax highlighting
    highlighter = new LuaSyntaxHighlighter(editor->document());

    contentLayout->addWidget(editor, 3);

    // Console header
    QLabel *consoleLabel = new QLabel("  CONSOLE");
    consoleLabel->setObjectName("consoleLabel");
    contentLayout->addWidget(consoleLabel);

    // Console
    console = new QTextEdit();
    console->setObjectName("console");
    console->setReadOnly(true);
    console->setFont(font);
    console->append("[Sirracha] Ready.");
    contentLayout->addWidget(console, 1);

    mainLayout->addWidget(content);

    // Apply stylesheet
    applyStyle();

    // Timer to check injection status
    statusTimer = new QTimer(this);
    connect(statusTimer, &QTimer::timeout, this, &SirrachaWindow::checkStatus);
    statusTimer->start(2000);

    // Fade in animation
    QGraphicsOpacityEffect *effect = new QGraphicsOpacityEffect(this);
    setGraphicsEffect(effect);
    QPropertyAnimation *anim = new QPropertyAnimation(effect, "opacity");
    anim->setDuration(300);
    anim->setStartValue(0.0);
    anim->setEndValue(1.0);
    anim->start(QAbstractAnimation::DeleteWhenStopped);
  }

private slots:
  void onInject() {
    console->append("[*] Injecting...");
    btnInject->setEnabled(false);

    QProcess *proc = new QProcess(this);
    proc->start("./inject_sober.sh", QStringList());
    proc->waitForFinished(10000);

    QString output =
        proc->readAllStandardOutput() + proc->readAllStandardError();
    if (output.contains("SUCCESS")) {
      console->append("[+] Injection successful!");
      statusLabel->setText("Connected");
      statusLabel->setStyleSheet("color: #50fa7b;");
      injected = true;
    } else {
      console->append("[-] Injection failed: " + output.left(200));
    }
    btnInject->setEnabled(true);
  }

  void onExecute() {
    if (!injected) {
      console->append("[-] Not injected! Click INJECT first.");
      return;
    }

    QString script = editor->toPlainText();
    console->append("[*] Executing script...");

    // Write script to IPC file
    QFile file("/tmp/sirracha_exec.txt");
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
      file.write(script.toUtf8());
      file.close();
    }

    // Wait and read output
    QTimer::singleShot(500, this, [this]() {
      QFile outFile("/tmp/sirracha_output.txt");
      if (outFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QString output = outFile.readAll();
        if (!output.isEmpty()) {
          console->append("[+] " + output);
        }
        outFile.close();
      }
    });
  }

  void onClear() { editor->clear(); }

  void onScriptSelected(QListWidgetItem *item) {
    QString name = item->text();
    if (name == "Hello World") {
      editor->setPlainText("-- Hello World\nprint(\"Hello from Sirracha!\")");
    } else if (name == "Speed Hack") {
      editor->setPlainText(
          "-- Speed Hack\nlocal player = game.Players.LocalPlayer\nlocal "
          "humanoid = "
          "player.Character:WaitForChild(\"Humanoid\")\nhumanoid.WalkSpeed = "
          "100\nprint(\"Speed set to 100!\")");
    } else if (name == "Fly Script") {
      editor->setPlainText("-- Fly Script\nprint(\"Fly script loaded!\")\n-- "
                           "Implementation here...");
    }
  }

  void checkStatus() {
    QFile ready("/tmp/sirracha_ready");
    if (ready.exists() && !injected) {
      statusLabel->setText("Connected");
      statusLabel->setStyleSheet("color: #50fa7b;");
      injected = true;
    }
  }

private:
  void applyStyle() {
    setStyleSheet(R"(
            * {
                font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
            }
            QMainWindow {
                background: #0a0a0a;
            }
            #sidebar {
                background: #141414;
                border-right: 1px solid #222;
            }
            #logo {
                font-size: 20px;
                font-weight: bold;
                color: #ff4444;
                padding: 8px 0 0 0;
                letter-spacing: 2px;
            }
            #version {
                color: #555;
                font-size: 11px;
                padding-bottom: 10px;
            }
            #status {
                color: #666;
                font-size: 12px;
                padding: 4px 8px;
                background: #1a1a1a;
                border-radius: 4px;
            }
            QPushButton {
                background: #1e1e1e;
                color: #ccc;
                border: 1px solid #333;
                padding: 12px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12px;
                letter-spacing: 1px;
            }
            QPushButton:hover {
                background: #2a2a2a;
                border-color: #444;
                color: #fff;
            }
            QPushButton:pressed {
                background: #333;
            }
            #btnInject {
                background: #ff4444;
                border: none;
                color: #fff;
            }
            #btnInject:hover {
                background: #ff5555;
            }
            #btnInject:pressed {
                background: #cc3333;
            }
            #sectionLabel {
                color: #555;
                font-size: 10px;
                font-weight: bold;
                letter-spacing: 2px;
                padding-top: 10px;
            }
            #scriptsList {
                background: #1a1a1a;
                border: 1px solid #222;
                border-radius: 6px;
                color: #aaa;
                padding: 4px;
            }
            #scriptsList::item {
                padding: 10px;
                border-radius: 4px;
                margin: 2px;
            }
            #scriptsList::item:selected {
                background: #2a2a2a;
                color: #fff;
            }
            #scriptsList::item:hover {
                background: #222;
            }
            #content {
                background: #0a0a0a;
            }
            #editorLabel, #consoleLabel {
                background: #1a1a1a;
                color: #ff4444;
                font-weight: bold;
                font-size: 10px;
                padding: 10px;
                letter-spacing: 2px;
                border-bottom: 1px solid #222;
            }
            #editor {
                background: #0d0d0d;
                color: #e0e0e0;
                border: none;
                padding: 12px;
                selection-background-color: #333;
            }
            #console {
                background: #0d0d0d;
                color: #777;
                border: none;
                border-top: 1px solid #1a1a1a;
                padding: 12px;
            }
            QScrollBar:vertical {
                background: #141414;
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #333;
                border-radius: 4px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #444;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
        )");
  }

  QPlainTextEdit *editor;
  QTextEdit *console;
  QListWidget *scriptsList;
  QLabel *statusLabel;
  QPushButton *btnInject, *btnExecute, *btnClear;
  LuaSyntaxHighlighter *highlighter;
  QTimer *statusTimer;
  bool injected = false;
};

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);

  SirrachaWindow window;
  window.show();

  return app.exec();
}

#include "SirrachaQt.moc"

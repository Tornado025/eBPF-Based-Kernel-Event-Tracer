import sys

from PySide6.QtCore import QProcess
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class EBPFRunner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("eBPF Script Runner")
        self.setGeometry(100, 100, 800, 600)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout(self.central_widget)

        self.output_display = QTextEdit()
        self.output_display.setReadOnly(True)
        self.layout.addWidget(self.output_display)

        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)

        self.create_buttons()

    def create_buttons(self):
        # In a real scenario, you might want to find these dynamically
        scripts = ["file_access", "memory_trace", "syscall_trace"]
        for script in scripts:
            button = QPushButton(f"Run {script}")
            button.clicked.connect(lambda checked, s=script: self.run_script(s))
            self.layout.addWidget(button)

    def run_script(self, script_name):
        self.output_display.clear()
        self.output_display.append(f"Running {script_name}...")

        # Run the user_loader with the compiled object file
        program = "sudo"
        args = ["./eBPF Scripts/user_loader", f"./eBPF Scripts/{script_name}.o"]

        # We start the process differently to handle arguments cleanly
        self.process.start(program, args)

    def handle_stdout(self):
        data = self.process.readAllStandardOutput()
        self.output_display.append(str(data.data(), "utf-8"))

    def handle_stderr(self):
        data = self.process.readAllStandardError()
        self.output_display.append(str(data.data(), "utf-8"))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EBPFRunner()
    window.show()
    sys.exit(app.exec())

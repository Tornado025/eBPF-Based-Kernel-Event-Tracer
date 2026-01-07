import json
import sys
from collections import defaultdict, deque

import pyqtgraph as pg
from PySide6.QtCore import QProcess
from PySide6.QtWidgets import (
    QApplication,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class ChartWidget(QWidget):
    """Individual chart with title"""

    def __init__(self, title):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: bold; font-size: 12px; padding: 5px;")
        layout.addWidget(title_label)

        # Plot
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground("w")
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.setMinimumHeight(250)
        layout.addWidget(self.plot_widget)

    def clear(self):
        self.plot_widget.clear()


class DashboardTab(QWidget):
    """Base class for each dashboard tab with grid layout"""

    def __init__(self, script_name):
        super().__init__()
        self.script_name = script_name
        self.data_buffer = deque(maxlen=1000)
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Scrollable area for charts
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        self.grid_layout = QGridLayout(scroll_content)
        self.grid_layout.setSpacing(10)
        scroll.setWidget(scroll_content)

        main_layout.addWidget(scroll, stretch=3)

        # Log output at bottom
        log_group = QGroupBox("Event Log")
        log_layout = QVBoxLayout()

        # Add copy button for logs
        log_controls = QHBoxLayout()
        self.copy_log_btn = QPushButton("Copy Logs")
        self.copy_log_btn.clicked.connect(self.copy_logs)
        log_controls.addWidget(self.copy_log_btn)
        log_controls.addStretch()
        log_layout.addLayout(log_controls)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        log_layout.addWidget(self.log_output)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group, stretch=1)

    def add_chart(self, chart, row, col):
        self.grid_layout.addWidget(chart, row, col)

    def copy_logs(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.log_output.toPlainText())

    def process_data(self, data_obj):
        """Override in subclasses"""
        self.log_output.append(json.dumps(data_obj))

    def clear_data(self):
        self.data_buffer.clear()
        self.log_output.clear()


class FileAccessTab(DashboardTab):
    def __init__(self):
        super().__init__("File Access")

        # Create charts
        self.chart1 = ChartWidget("File Operations Over Time")
        self.chart2 = ChartWidget("Operations by Type")
        self.chart3 = ChartWidget("Event Rate (ops/sec)")
        self.chart4 = ChartWidget("CPU Distribution")

        # Add to grid (2 columns)
        self.add_chart(self.chart1, 0, 0)
        self.add_chart(self.chart2, 0, 1)
        self.add_chart(self.chart3, 1, 0)
        self.add_chart(self.chart4, 1, 1)

        # Data tracking
        self.time_data = []
        self.total_events = []
        self.event_types = defaultdict(int)
        self.cpu_counts = defaultdict(int)
        self.last_time = 0

    def process_data(self, data_obj):
        if data_obj.get("type") == "data":
            current_time = len(self.time_data)
            self.time_data.append(current_time)
            self.total_events.append(len(self.total_events) + 1)

            # Track CPU
            cpu = data_obj.get("cpu", 0)
            self.cpu_counts[cpu] += 1

            # Update Chart 1: Total operations over time
            self.chart1.clear()
            self.chart1.plot_widget.plot(
                self.time_data, self.total_events, pen=pg.mkPen("b", width=2)
            )
            self.chart1.plot_widget.setLabel("left", "Total Operations")
            self.chart1.plot_widget.setLabel("bottom", "Time (events)")

            # Update Chart 4: CPU distribution
            self.chart4.clear()
            cpus = list(self.cpu_counts.keys())
            counts = [self.cpu_counts[c] for c in cpus]
            bg = pg.BarGraphItem(x=cpus, height=counts, width=0.6, brush="b")
            self.chart4.plot_widget.addItem(bg)
            self.chart4.plot_widget.setLabel("left", "Event Count")
            self.chart4.plot_widget.setLabel("bottom", "CPU")

    def clear_data(self):
        super().clear_data()
        self.time_data.clear()
        self.total_events.clear()
        self.event_types.clear()
        self.cpu_counts.clear()
        self.chart1.clear()
        self.chart2.clear()
        self.chart3.clear()
        self.chart4.clear()


class MemoryTraceTab(DashboardTab):
    def __init__(self):
        super().__init__("Memory Trace")

        # Create charts
        self.chart1 = ChartWidget("Memory Events Over Time")
        self.chart2 = ChartWidget("Event Size Distribution")
        self.chart3 = ChartWidget("CPU Activity")
        self.chart4 = ChartWidget("Event Rate")

        # Add to grid
        self.add_chart(self.chart1, 0, 0)
        self.add_chart(self.chart2, 0, 1)
        self.add_chart(self.chart3, 1, 0)
        self.add_chart(self.chart4, 1, 1)

        # Data tracking
        self.time_data = []
        self.event_sizes = []
        self.cpu_counts = defaultdict(int)

    def process_data(self, data_obj):
        if data_obj.get("type") == "data":
            current_time = len(self.time_data)
            size = data_obj.get("size", 0)
            cpu = data_obj.get("cpu", 0)

            self.time_data.append(current_time)
            self.event_sizes.append(size)
            self.cpu_counts[cpu] += 1

            # Chart 1: Events over time
            self.chart1.clear()
            self.chart1.plot_widget.plot(
                self.time_data, range(len(self.time_data)), pen=pg.mkPen("g", width=2)
            )
            self.chart1.plot_widget.setLabel("left", "Event Count")
            self.chart1.plot_widget.setLabel("bottom", "Time")

            # Chart 2: Size distribution
            self.chart2.clear()
            self.chart2.plot_widget.plot(
                self.time_data, self.event_sizes, pen=pg.mkPen("r", width=2)
            )
            self.chart2.plot_widget.setLabel("left", "Event Size (bytes)")
            self.chart2.plot_widget.setLabel("bottom", "Time")

            # Chart 3: CPU activity
            self.chart3.clear()
            cpus = list(self.cpu_counts.keys())
            counts = [self.cpu_counts[c] for c in cpus]
            bg = pg.BarGraphItem(x=cpus, height=counts, width=0.6, brush="g")
            self.chart3.plot_widget.addItem(bg)
            self.chart3.plot_widget.setLabel("left", "Events")
            self.chart3.plot_widget.setLabel("bottom", "CPU")

    def clear_data(self):
        super().clear_data()
        self.time_data.clear()
        self.event_sizes.clear()
        self.cpu_counts.clear()
        self.chart1.clear()
        self.chart2.clear()
        self.chart3.clear()
        self.chart4.clear()


class SyscallTraceTab(DashboardTab):
    def __init__(self):
        super().__init__("Syscall Trace")

        # Create charts
        self.chart1 = ChartWidget("Syscall Events Over Time")
        self.chart2 = ChartWidget("Event Size Trend")
        self.chart3 = ChartWidget("CPU Distribution")
        self.chart4 = ChartWidget("Activity Heatmap")

        # Add to grid
        self.add_chart(self.chart1, 0, 0)
        self.add_chart(self.chart2, 0, 1)
        self.add_chart(self.chart3, 1, 0)
        self.add_chart(self.chart4, 1, 1)

        # Data tracking
        self.time_data = []
        self.event_sizes = []
        self.cpu_counts = defaultdict(int)

    def process_data(self, data_obj):
        if data_obj.get("type") == "data":
            current_time = len(self.time_data)
            size = data_obj.get("size", 0)
            cpu = data_obj.get("cpu", 0)

            self.time_data.append(current_time)
            self.event_sizes.append(size)
            self.cpu_counts[cpu] += 1

            # Chart 1: Syscalls over time
            self.chart1.clear()
            self.chart1.plot_widget.plot(
                self.time_data, range(len(self.time_data)), pen=pg.mkPen("r", width=2)
            )
            self.chart1.plot_widget.setLabel("left", "Syscall Count")
            self.chart1.plot_widget.setLabel("bottom", "Time")

            # Chart 2: Event sizes
            self.chart2.clear()
            self.chart2.plot_widget.plot(
                self.time_data, self.event_sizes, pen=pg.mkPen("#ff6b6b", width=2)
            )
            self.chart2.plot_widget.setLabel("left", "Event Size (bytes)")
            self.chart2.plot_widget.setLabel("bottom", "Time")

            # Chart 3: CPU distribution
            self.chart3.clear()
            cpus = list(self.cpu_counts.keys())
            counts = [self.cpu_counts[c] for c in cpus]
            bg = pg.BarGraphItem(x=cpus, height=counts, width=0.6, brush="r")
            self.chart3.plot_widget.addItem(bg)
            self.chart3.plot_widget.setLabel("left", "Syscalls")
            self.chart3.plot_widget.setLabel("bottom", "CPU")

    def clear_data(self):
        super().clear_data()
        self.time_data.clear()
        self.event_sizes.clear()
        self.cpu_counts.clear()
        self.chart1.clear()
        self.chart2.clear()
        self.chart3.clear()
        self.chart4.clear()


class EBPFRunner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("eBPF Script Runner")
        self.setGeometry(100, 100, 1200, 800)

        self.current_script = None
        self.setup_ui()

        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.stateChanged.connect(self.update_ui_state)

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)

        # Create tabs
        self.tabs = QTabWidget()
        self.file_tab = FileAccessTab()
        self.memory_tab = MemoryTraceTab()
        self.syscall_tab = SyscallTraceTab()

        self.tabs.addTab(self.file_tab, "File Access")
        self.tabs.addTab(self.memory_tab, "Memory Trace")
        self.tabs.addTab(self.syscall_tab, "Syscall Trace")

        main_layout.addWidget(self.tabs, stretch=4)

        # Control panel on the right
        control_layout = QVBoxLayout()

        control_label = QLabel("Control Panel")
        control_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        control_layout.addWidget(control_label)

        # Current tab label
        self.current_tab_label = QLabel("Selected: File Access")
        self.current_tab_label.setStyleSheet(
            "padding: 10px; background-color: #f0f0f0; border-radius: 5px;"
        )
        control_layout.addWidget(self.current_tab_label)

        # Single start button that works with current tab
        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_current_script)
        self.start_button.setStyleSheet(
            "background-color: #51cf66; color: white; padding: 10px; font-weight: bold;"
        )
        control_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_script)
        self.stop_button.setStyleSheet(
            "background-color: #ff6b6b; color: white; padding: 10px; font-weight: bold;"
        )
        control_layout.addWidget(self.stop_button)

        # Quit button
        self.quit_button = QPushButton("Quit")
        self.quit_button.clicked.connect(self.close)
        self.quit_button.setStyleSheet("padding: 10px; margin-top: 20px;")
        control_layout.addWidget(self.quit_button)

        control_layout.addStretch()

        # Connect tab change to update label
        self.tabs.currentChanged.connect(self.update_current_tab_label)

        main_layout.addLayout(control_layout, stretch=1)

    def update_current_tab_label(self):
        tab_names = ["File Access", "Memory Trace", "Syscall Trace"]
        current_index = self.tabs.currentIndex()
        self.current_tab_label.setText(f"Selected: {tab_names[current_index]}")

    def start_current_script(self):
        # Get script name based on current tab
        script_names = ["file_access", "memory_trace", "syscall_trace"]
        current_index = self.tabs.currentIndex()
        script_name = script_names[current_index]

        # Clear current tab
        current_tab = self.tabs.currentWidget()
        if current_tab:
            current_tab.clear_data()

        self.current_script = script_name

        # Run the loader
        program = "sudo"
        args = ["./eBPF Scripts/user_loader", f"./eBPF Scripts/{script_name}.o"]
        self.process.start(program, args)

    def stop_script(self):
        if self.process.state() == QProcess.ProcessState.Running:
            self.process.terminate()
            # Give it 2 seconds to terminate gracefully
            if not self.process.waitForFinished(2000):
                self.process.kill()
                self.process.waitForFinished(1000)

    def closeEvent(self, event):
        """Clean up processes before closing"""
        if self.process.state() == QProcess.ProcessState.Running:
            self.process.terminate()
            if not self.process.waitForFinished(2000):
                self.process.kill()
                self.process.waitForFinished(1000)
        event.accept()

    def update_ui_state(self):
        is_running = self.process.state() == QProcess.ProcessState.Running
        # Stop button should be ENABLED when running, disabled when not
        self.stop_button.setEnabled(is_running)
        # Start button should be ENABLED when not running, disabled when running
        self.start_button.setEnabled(not is_running)

    def handle_stdout(self):
        data = self.process.readAllStandardOutput()
        text = str(data.data(), "utf-8")

        # Get the tab that started the script, not necessarily the current one
        script_names = ["file_access", "memory_trace", "syscall_trace"]
        tabs = [self.file_tab, self.memory_tab, self.syscall_tab]

        try:
            script_index = script_names.index(self.current_script)
            target_tab = tabs[script_index]
        except (ValueError, AttributeError):
            target_tab = self.tabs.currentWidget()

        for line in text.strip().split("\n"):
            if not line:
                continue

            # Always show in log first
            if hasattr(target_tab, "log_output"):
                target_tab.log_output.append(line)

            try:
                data_obj = json.loads(line)
                if target_tab:
                    target_tab.process_data(data_obj)
            except json.JSONDecodeError:
                # Already appended to log above
                pass

    def handle_stderr(self):
        data = self.process.readAllStandardError()
        text = str(data.data(), "utf-8")

        # Route to the tab that started the script
        script_names = ["file_access", "memory_trace", "syscall_trace"]
        tabs = [self.file_tab, self.memory_tab, self.syscall_tab]

        try:
            script_index = script_names.index(self.current_script)
            target_tab = tabs[script_index]
        except (ValueError, AttributeError):
            target_tab = self.tabs.currentWidget()

        if hasattr(target_tab, "log_output"):
            target_tab.log_output.append(f"ERROR: {text}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EBPFRunner()
    window.show()
    sys.exit(app.exec())

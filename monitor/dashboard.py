import tkinter as tk


class IDSDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("IDS Monitor")
        self.root.geometry("600x400")
        self.root.configure(bg="#0f172a")

        self.status_label = tk.Label(root, font=("Consolas", 16), bg="#0f172a")
        self.status_label.pack(pady=10)

        self.ai_label = tk.Label(root, font=("Consolas", 14), bg="#0f172a")
        self.ai_label.pack()

        self.conf_bar = tk.Label(root, font=("Consolas", 12), bg="#0f172a")
        self.conf_bar.pack(pady=5)

        self.activity_label = tk.Label(
            root, font=("Consolas", 12), bg="#0f172a")
        self.activity_label.pack(pady=10)

        self.event_label = tk.Label(root, font=("Consolas", 12), bg="#0f172a")
        self.event_label.pack(pady=10)

        self.baseline_label = tk.Label(
            root, font=("Consolas", 12), bg="#0f172a")
        self.baseline_label.pack(pady=10)

    def build_bar(self, confidence):
        total = 20
        filled = int(confidence * total)
        return "█" * filled + "░" * (total - filled)

    def update(self, state):
        if not state:
            return

        severity = state.get("severity", "LOW")

        if severity == "CRITICAL":
            color = "#ff4d4d"
            status = "🔴 UNDER ATTACK"
        elif severity == "HIGH":
            color = "#ff944d"
            status = "🟠 SUSPICIOUS"
        elif severity == "MEDIUM":
            color = "#ffd11a"
            status = "🟡 WATCH"
        else:
            color = "#00ff99"
            status = "🟢 SAFE"

        self.status_label.config(text=f"STATUS: {status}", fg=color)

        self.ai_label.config(
            text=f"AI: {state.get('ai_type', '').upper()}",
            fg=color
        )

        bar = self.build_bar(state.get("confidence", 0))
        self.conf_bar.config(
            text=f"[{bar}] {state.get('confidence', 0):.2f}", fg="#38bdf8")

        self.activity_label.config(
            text=(
                f"MODIFIED: {state.get('modified', 0)}   "
                f"DELETED: {state.get('deleted', 0)}   "
                f"NEW: {state.get('new', 0)}"
            ),
            fg="#e2e8f0"
        )

        self.event_label.config(
            text=f"LAST: {state.get('last_event', 'None')}",
            fg="#cbd5f5"
        )

        baseline = state.get("baseline_issues", [])
        if baseline:
            self.baseline_label.config(
                text="⚠ Baseline Issues:\n" + "\n".join(baseline),
                fg="#ff4d4d"
            )
        else:
            self.baseline_label.config(
                text="✔ Baseline OK",
                fg="#00ff99"
            )

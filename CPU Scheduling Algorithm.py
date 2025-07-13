import tkinter as tk
from tkinter import ttk, messagebox

class CPUSchedulerSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("CPU Scheduling Simulator")
        self.root.geometry("1000x600")
        self.root.configure(bg="#f0f0f5")

        self.process_list = []

        self.main_frame = tk.Frame(root, bg="#ffffff", bd=2, relief="groove")
        self.main_frame.pack(padx=20, pady=20, fill="both", expand=True)

        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(
            self.main_frame,
            text="CPU Scheduling Simulator",
            font=("Segoe UI", 20, "bold"),
            bg="#ffffff",
            fg="#4B0082"
        )
        title.pack(pady=20)

        input_frame = tk.Frame(self.main_frame, bg="#ffffff")
        input_frame.pack(pady=10)

        label_style = {"bg": "#ffffff", "font": ("Segoe UI", 11)}
        tk.Label(input_frame, text="Process ID", **label_style).grid(row=0, column=0, padx=10)
        tk.Label(input_frame, text="Arrival Time", **label_style).grid(row=0, column=1, padx=10)
        tk.Label(input_frame, text="Burst Time", **label_style).grid(row=0, column=2, padx=10)
        tk.Label(input_frame, text="Priority", **label_style).grid(row=0, column=3, padx=10)

        entry_style = {"width": 10, "bg": "#e6f2ff", "fg": "#333", "font": ("Segoe UI", 10)}
        self.entry_pid = tk.Entry(input_frame, **entry_style)
        self.entry_at = tk.Entry(input_frame, **entry_style)
        self.entry_bt = tk.Entry(input_frame, **entry_style)
        self.entry_priority = tk.Entry(input_frame, **entry_style)

        self.entry_pid.grid(row=1, column=0, padx=5)
        self.entry_at.grid(row=1, column=1, padx=5)
        self.entry_bt.grid(row=1, column=2, padx=5)
        self.entry_priority.grid(row=1, column=3, padx=5)

        tk.Button(
            input_frame,
            text="Add Process",
            bg="#4CAF50", fg="white",
            font=("Segoe UI", 10, "bold"),
            activebackground="#45a049",
            command=self.add_process
        ).grid(row=1, column=4, padx=15)

        algo_frame = tk.Frame(self.main_frame, bg="#ffffff")
        algo_frame.pack(pady=10)

        tk.Label(algo_frame, text="Select Algorithm:", font=("Segoe UI", 11), bg="#ffffff").pack(side=tk.LEFT)
        self.algo_var = tk.StringVar()
        self.algo_dropdown = ttk.Combobox(algo_frame, textvariable=self.algo_var, state="readonly", width=25)
        self.algo_dropdown['values'] = ("FCFS", "SJF", "Priority", "Round Robin")
        self.algo_dropdown.pack(side=tk.LEFT, padx=10)

        self.quantum_label = tk.Label(algo_frame, text="Time Quantum:", font=("Segoe UI", 11), bg="#ffffff")
        self.quantum_entry = tk.Entry(algo_frame, width=5, font=("Segoe UI", 10))
        self.quantum_label.pack(side=tk.LEFT, padx=10)
        self.quantum_entry.pack(side=tk.LEFT)

        table_frame = tk.Frame(self.main_frame)
        table_frame.pack(pady=15, fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview.Heading", font=("Segoe UI", 11, "bold"), background="#4B0082", foreground="white")
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=25, background="#ffffff", fieldbackground="#ffffff")

        self.tree = ttk.Treeview(table_frame, columns=("PID", "AT", "BT", "Priority"), show="headings", height=6)
        for col in ("PID", "AT", "BT", "Priority"):
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")
        self.tree.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        tk.Button(
            self.main_frame,
            text="Simulate",
            bg="#6a5acd", fg="white",
            font=("Segoe UI", 12, "bold"),
            activebackground="#5a4bb0",
            command=self.simulate
        ).pack(pady=15)

    def add_process(self):
        try:
            pid = self.entry_pid.get()
            at = int(self.entry_at.get())
            bt = int(self.entry_bt.get())
            priority = self.entry_priority.get()
            priority = int(priority) if priority else None

            self.process_list.append({"pid": pid, "at": at, "bt": bt, "priority": priority})
            self.tree.insert('', 'end', values=(pid, at, bt, priority))
            self.clear_entries()
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid numeric values.")

    def clear_entries(self):
        self.entry_pid.delete(0, tk.END)
        self.entry_at.delete(0, tk.END)
        self.entry_bt.delete(0, tk.END)
        self.entry_priority.delete(0, tk.END)

    def simulate(self):
        algo = self.algo_var.get()
        if not algo:
            messagebox.showwarning("Algorithm Not Selected", "Please select a scheduling algorithm.")
            return

        if algo == "FCFS":
            self.simulate_fcfs()
        elif algo == "SJF":
            self.simulate_sjf()
        elif algo == "Priority":
            self.simulate_priority()
        elif algo == "Round Robin":
            try:
                quantum = int(self.quantum_entry.get())
                self.simulate_rr(quantum)
            except:
                messagebox.showerror("Invalid Input", "Please enter a valid time quantum.")

    def simulate_fcfs(self):
        processes = sorted(self.process_list, key=lambda x: x['at'])
        time, wt, tat = 0, [], []
        for p in processes:
            if time < p['at']:
                time = p['at']
            start = time
            time += p['bt']
            tat.append(time - p['at'])
            wt.append(start - p['at'])
        self.show_result(processes, wt, tat)

    def simulate_sjf(self):
        processes = sorted(self.process_list, key=lambda x: (x['at'], x['bt']))
        time, completed, wt, tat = 0, [], {}, {}
        while len(completed) < len(processes):
            ready = [p for p in processes if p['at'] <= time and p['pid'] not in completed]
            if not ready:
                time += 1
                continue
            current = min(ready, key=lambda x: x['bt'])
            start = time
            time += current['bt']
            tat[current['pid']] = time - current['at']
            wt[current['pid']] = start - current['at']
            completed.append(current['pid'])
        result = [p for p in processes if p['pid'] in completed]
        self.show_result(result, [wt[p['pid']] for p in result], [tat[p['pid']] for p in result])

    def simulate_priority(self):
        processes = sorted(self.process_list, key=lambda x: (x['at'], x['priority']))
        time, completed, wt, tat = 0, [], {}, {}
        while len(completed) < len(processes):
            ready = [p for p in processes if p['at'] <= time and p['pid'] not in completed]
            if not ready:
                time += 1
                continue
            current = min(ready, key=lambda x: x['priority'])
            start = time
            time += current['bt']
            tat[current['pid']] = time - current['at']
            wt[current['pid']] = start - current['at']
            completed.append(current['pid'])
        result = [p for p in processes if p['pid'] in completed]
        self.show_result(result, [wt[p['pid']] for p in result], [tat[p['pid']] for p in result])

    def simulate_rr(self, quantum):
        from collections import deque
        processes = sorted(self.process_list, key=lambda x: x['at'])
        n = len(processes)
        time = 0
        queue = deque()
        remaining_bt = {p['pid']: p['bt'] for p in processes}
        at_dict = {p['pid']: p['at'] for p in processes}
        pid_to_process = {p['pid']: p for p in processes}
        wt, tat = {}, {}
        queue.extend([p for p in processes if p['at'] == time])
        seen = set(p['pid'] for p in queue)

        while len(tat) < n:
            if queue:
                current = queue.popleft()
                pid = current['pid']
                bt = remaining_bt[pid]
                exec_time = min(bt, quantum)
                time += exec_time
                remaining_bt[pid] -= exec_time
                for p in processes:
                    if p['at'] <= time and p['pid'] not in seen and p['pid'] not in tat:
                        queue.append(p)
                        seen.add(p['pid'])
                if remaining_bt[pid] > 0:
                    queue.append(current)
                else:
                    tat[pid] = time - at_dict[pid]
                    wt[pid] = tat[pid] - pid_to_process[pid]['bt']
            else:
                time += 1
                for p in processes:
                    if p['at'] == time and p['pid'] not in seen:
                        queue.append(p)
                        seen.add(p['pid'])

        result = [pid_to_process[pid] for pid in pid_to_process]
        self.show_result(result, [wt[p['pid']] for p in result], [tat[p['pid']] for p in result])

    def show_result(self, processes, wt, tat):
        result = "PID\tAT\tBT\tWT\tTAT\n"
        for i, p in enumerate(processes):
            result += f"{p['pid']}\t{p['at']}\t{p['bt']}\t{wt[i]}\t{tat[i]}\n"
        avg_wt = sum(wt) / len(wt)
        avg_tat = sum(tat) / len(tat)
        result += f"\nAverage Waiting Time: {avg_wt:.2f}\nAverage Turnaround Time: {avg_tat:.2f}"
        messagebox.showinfo("Simulation Result", result)

if __name__ == "__main__":
    root = tk.Tk()
    app = CPUSchedulerSimulator(root)
    root.mainloop()

import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from trading import Trader  # adjust import path if needed
from strategies import (
    SafeStrategy, ModerateStrategy, AggressiveStrategy,
    MomentumStrategy, MeanReversionStrategy
)


class MainApplication(tk.Tk):
    def __init__(self, settings):
        super().__init__()
        self.title("Forex Scalper")

        # make window resizable
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.settings = settings
        self.trader = Trader(self.settings)

        container = ttk.Frame(self)
        container.grid(row=0, column=0, sticky="nsew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        self.pages = {}
        for Page in (SettingsPage, TradingPage):
            page = Page(container, self)
            page.grid(row=0, column=0, sticky="nsew")
            self.pages[Page] = page

        self.show_page(SettingsPage)

    def show_page(self, page_cls):
        self.pages[page_cls].tkraise()


class SettingsPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=10)
        self.controller = controller
        self.columnconfigure(0, weight=1)

        # --- Login Settings ---
        creds = ttk.Labelframe(self, text="Login Settings", padding=10)
        creds.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        creds.columnconfigure(1, weight=1)

        ttk.Label(creds, text="Host:").grid(row=0, column=0, sticky="w", padx=(0,5))
        self.host_var = tk.StringVar()
        ttk.Entry(creds, textvariable=self.host_var).grid(row=0, column=1, sticky="ew")

        ttk.Label(creds, text="Port:").grid(row=1, column=0, sticky="w", padx=(0,5))
        self.port_var = tk.IntVar()
        ttk.Entry(creds, textvariable=self.port_var).grid(row=1, column=1, sticky="ew")

        ttk.Label(creds, text="SenderCompID:").grid(row=2, column=0, sticky="w", padx=(0,5))
        self.sender_var = tk.StringVar()
        ttk.Entry(creds, textvariable=self.sender_var).grid(row=2, column=1, sticky="ew")

        ttk.Label(creds, text="TargetCompID:").grid(row=3, column=0, sticky="w", padx=(0,5))
        self.target_var = tk.StringVar()
        ttk.Entry(creds, textvariable=self.target_var).grid(row=3, column=1, sticky="ew")

        ttk.Label(creds, text="Password:").grid(row=4, column=0, sticky="w", padx=(0,5))
        self.password_var = tk.StringVar()
        ttk.Entry(creds, textvariable=self.password_var, show="*").grid(row=4, column=1, sticky="ew")

        # --- Account Summary ---
        acct = ttk.Labelframe(self, text="Account Summary", padding=10)
        acct.grid(row=1, column=0, sticky="ew", pady=(0,10))
        acct.columnconfigure(1, weight=1)

        self.account_id_var = tk.StringVar(value="–")
        ttk.Label(acct, text="Account ID:").grid(row=0, column=0, sticky="w", padx=(0,5))
        ttk.Label(acct, textvariable=self.account_id_var).grid(row=0, column=1, sticky="w")

        self.balance_var = tk.StringVar(value="–")
        ttk.Label(acct, text="Balance:").grid(row=1, column=0, sticky="w", padx=(0,5))
        ttk.Label(acct, textvariable=self.balance_var).grid(row=1, column=1, sticky="w")

        self.equity_var = tk.StringVar(value="–")
        ttk.Label(acct, text="Equity:").grid(row=2, column=0, sticky="w", padx=(0,5))
        ttk.Label(acct, textvariable=self.equity_var).grid(row=2, column=1, sticky="w")

        self.margin_var = tk.StringVar(value="–")
        ttk.Label(acct, text="Margin:").grid(row=3, column=0, sticky="w", padx=(0,5))
        ttk.Label(acct, textvariable=self.margin_var).grid(row=3, column=1, sticky="w")

        # --- Actions & Status ---
        actions = ttk.Frame(self)
        actions.grid(row=2, column=0, sticky="ew", pady=(10,0))
        ttk.Button(actions, text="Save Settings", command=self.save_settings).pack(side="left", padx=5)
        ttk.Button(actions, text="Connect", command=self.attempt_connection).pack(side="left", padx=5)

        self.status = ttk.Label(self, text="Disconnected", anchor="center")
        self.status.grid(row=3, column=0, sticky="ew", pady=(5,0))

    def save_settings(self):
        s = self.controller.settings
        s.fix_host = self.host_var.get()
        s.fix_port = self.port_var.get()
        s.fix_sender_comp_id = self.sender_var.get()
        s.fix_target_comp_id = self.target_var.get()
        s.fix_password = self.password_var.get()

    def attempt_connection(self):
        self.save_settings()
        t = self.controller.trader

        # Re-init FIX params on the Trader
        t.settings = self.controller.settings
        t.fix_host = t.settings.fix_host
        t.fix_port = t.settings.fix_port
        t.fix_sender_comp_id = t.settings.fix_sender_comp_id
        t.fix_target_comp_id = t.settings.fix_target_comp_id
        t.fix_password = t.settings.fix_password

        if t.connect():
            self.status.config(text="Connecting...", foreground="orange")
            self.after(100, self._check_connection)
        else:
            _, msg = t.get_connection_status()
            messagebox.showerror("Connection Failed", msg)
            self.status.config(text=f"Failed: {msg}", foreground="red")

    # Poll connection status until connected or error
    def _check_connection(self):
        t = self.controller.trader
        connected, msg = t.get_connection_status()
        if connected:
            # proceed to post-connection
            self._extracted_from_attempt_connection_14(t)
        else:
            if msg:
                messagebox.showerror("Connection Failed", msg)
                self.status.config(text=f"Failed: {msg}", foreground="red")
            else:
                self.after(200, self._check_connection)

    # TODO Rename this here and in `attempt_connection`
            _, msg = t.get_connection_status()
            messagebox.showerror("Connection Failed", msg)
            self.status.config(text=f"Failed: {msg}", foreground="red")

    # TODO Rename this here and in `attempt_connection`
    def _extracted_from_attempt_connection_14(self, t):
        t.start_heartbeat()
        summary = t.get_account_summary()
        self.account_id_var.set(summary.get("account_id", "–"))
        self.balance_var.set(f"{summary['balance']:.2f}")
        self.equity_var.set(f"{summary['equity']:.2f}")
        self.margin_var.set(f"{summary['margin']:.2f}")
        messagebox.showinfo(
            "Connected",
            f"Successfully connected!\n\n"
            f"Account ID: {summary['account_id']}\n"
            f"Balance: {summary['balance']:.2f}\n"
            f"Equity: {summary['equity']:.2f}\n"
            f"Margin: {summary['margin']:.2f}"
        )
        self.status.config(text="Connected ✅", foreground="green")
        self.controller.show_page(TradingPage)


class TradingPage(ttk.Frame):
    COMMON_PAIRS = ["EUR/USD", "GBP/USD", "USD/JPY", "USD/CHF", "AUD/USD", "NZD/USD"]

    def __init__(self, parent, controller):
        super().__init__(parent, padding=10)
        self.controller = controller
        self.trader = controller.trader

        # Thread-safe event queue for UI updates
        self._ui_queue = queue.Queue()
        self.after(100, self._process_ui_queue)

        self.is_scalping = False
        self.scalping_thread = None

        # configure grid
        for r in range(11):
            self.rowconfigure(r, weight=0)
        self.rowconfigure(11, weight=1)
        self.columnconfigure(1, weight=1)

        # ← Settings button
        ttk.Button(self, text="← Settings", command=lambda: controller.show_page(SettingsPage)).grid(
            row=0, column=0, pady=(0,10), sticky="w"
        )

        # Symbol dropdown
        ttk.Label(self, text="Symbol:").grid(row=1, column=0, sticky="w", padx=(0,5))
        self.symbol_var = tk.StringVar(value=self.COMMON_PAIRS[0])
        cb_symbol = ttk.Combobox(self, textvariable=self.symbol_var,
                                 values=self.COMMON_PAIRS, state="readonly")
        cb_symbol.grid(row=1, column=1, sticky="ew")
        cb_symbol.bind("<<ComboboxSelected>>", lambda e: self.refresh_price())

        # Price display + refresh
        ttk.Label(self, text="Price:").grid(row=2, column=0, sticky="w", padx=(0,5))
        self.price_var = tk.StringVar(value="–")
        pf = ttk.Frame(self)
        pf.grid(row=2, column=1, sticky="ew")
        ttk.Label(pf, textvariable=self.price_var,
                  font=("TkDefaultFont", 12, "bold")).pack(side="left")
        ttk.Button(pf, text="↻", width=2, command=self.refresh_price).pack(side="right")

        # Profit target
        ttk.Label(self, text="Profit Target (pips):").grid(row=3, column=0, sticky="w", padx=(0,5))
        self.tp_var = tk.DoubleVar(value=10.0)
        ttk.Entry(self, textvariable=self.tp_var).grid(row=3, column=1, sticky="ew")

        # Order size
        ttk.Label(self, text="Order Size (lots):").grid(row=4, column=0, sticky="w", padx=(0,5))
        self.size_var = tk.DoubleVar(value=1.0)
        ttk.Entry(self, textvariable=self.size_var).grid(row=4, column=1, sticky="ew")

        # Stop-loss
        ttk.Label(self, text="Stop Loss (pips):").grid(row=5, column=0, sticky="w", padx=(0,5))
        self.sl_var = tk.DoubleVar(value=5.0)
        ttk.Entry(self, textvariable=self.sl_var).grid(row=5, column=1, sticky="ew")

        # Strategy selector
        ttk.Label(self, text="Strategy:").grid(row=6, column=0, sticky="w", padx=(0,5))
        self.strategy_var = tk.StringVar(value="Safe")
        strategy_names = ["Safe", "Moderate", "Aggressive", "Momentum", "Mean Reversion"]
        cb_strat = ttk.Combobox(self, textvariable=self.strategy_var, values=strategy_names, state="readonly")
        cb_strat.grid(row=6, column=1, sticky="ew")

        # Start/Stop Scalping buttons
        self.start_button = ttk.Button(self, text="Begin Scalping", command=self.start_scalping)
        self.start_button.grid(row=7, column=0, columnspan=2, pady=(10,0))
        self.stop_button  = ttk.Button(self, text="Stop Scalping", command=self.stop_scalping, state="disabled")
        self.stop_button.grid(row=8, column=0, columnspan=2, pady=(5,0))

        # Session Stats frame
        stats = ttk.Labelframe(self, text="Session Stats", padding=10)
        stats.grid(row=9, column=0, columnspan=2, sticky="ew", pady=(10,0))
        stats.columnconfigure(1, weight=1)

        self.pnl_var       = tk.StringVar(value="0.00")
        self.trades_var    = tk.StringVar(value="0")
        self.win_rate_var = tk.StringVar(value="0%")

        ttk.Label(stats, text="P&L:").grid(row=0, column=0, sticky="w", padx=(0,5))
        ttk.Label(stats, textvariable=self.pnl_var).grid(row=0, column=1, sticky="w")
        ttk.Label(stats, text="# Trades:").grid(row=1, column=0, sticky="w", padx=(0,5))
        ttk.Label(stats, textvariable=self.trades_var).grid(row=1, column=1, sticky="w")
        ttk.Label(stats, text="Win Rate:").grid(row=2, column=0, sticky="w", padx=(0,5))
        ttk.Label(stats, textvariable=self.win_rate_var).grid(row=2, column=1, sticky="w")

        # Output log
        self.output = tk.Text(self, height=8, wrap="word", state="disabled")
        self.output.grid(row=11, column=0, columnspan=2, sticky="nsew", pady=(10,0))
        sb = ttk.Scrollbar(self, command=self.output.yview)
        sb.grid(row=11, column=2, sticky="ns")
        self.output.config(yscrollcommand=sb.set)

        # Internal counters
        self.total_pnl    = 0.0
        self.total_trades = 0
        self.wins         = 0

        self.refresh_price()

    def _process_ui_queue(self):
        """Called on the mainloop to drain the UI event queue."""
        try:
            while True:
                func, args = self._ui_queue.get_nowait()
                func(*args)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_ui_queue)

    def refresh_price(self):
        symbol = self.symbol_var.get().replace("/", "")
        try:
            price = self.trader.get_market_price(symbol)
            self.price_var.set(f"{price:.5f}")
            self._log(f"Refreshed price for {symbol}: {price:.5f}")
        except Exception as e:
            self.price_var.set("ERR")
            self._log(f"Error fetching price: {e}")

    def start_scalping(self):
        if self.is_scalping:
            return

        # instantiate strategy
        sel = self.strategy_var.get()
        if sel == "Safe":
            strategy = SafeStrategy()
        elif sel == "Moderate":
            strategy = ModerateStrategy()
        elif sel == "Aggressive":
            strategy = AggressiveStrategy()
        elif sel == "Mean Reversion":
            strategy = MeanReversionStrategy()
        else:
            strategy = MomentumStrategy()

        # Snapshot GUI inputs on main thread
        symbol = self.symbol_var.get().replace("/", "")
        tp     = self.tp_var.get()
        sl     = self.sl_var.get()
        size   = self.size_var.get()

        self._toggle_scalping_ui(True)
        self.scalping_thread = threading.Thread(
            target=self._scalp_loop,
            args=(symbol, tp, sl, size, strategy),
            daemon=True
        )
        self.scalping_thread.start()

    def stop_scalping(self):
        if self.is_scalping:
            self._toggle_scalping_ui(False)

    def _toggle_scalping_ui(self, on: bool):
        self.is_scalping = on
        state_start = "disabled" if on else "normal"
        state_stop  = "normal"   if on else "disabled"
        self.start_button.config(state=state_start)
        self.stop_button.config(state=state_stop)

    def _scalp_loop(self, symbol: str, tp: float, sl: float, size: float, strategy):
        """Background thread: pure logic, enqueues UI updates."""
        while self.is_scalping:
            price   = self.trader.get_market_price(symbol)
            history = self.trader.price_history
            action  = strategy.decide({"prices": history})

            if action in ("buy", "sell"):
                # enqueue an _execute_trade call
                self._ui_queue.put((
                    self._execute_trade,
                    (action, symbol, price, size, tp, sl)
                ))
            else:
                self._ui_queue.put((self._log, ("HOLD signal; skipping trade.",)))

            time.sleep(1)

    def _execute_trade(self,
                       side: str,
                       symbol: str,
                       price: float,
                       size: float,
                       tp: float,
                       sl: float):
        """Runs on the Tk mainloop—safe to update UI."""
        self._log(f"{side.upper()} scalp: {symbol} at {price:.5f} | "
                  f"size={size} lots | SL={sl} pips | TP={tp} pips")
        # Here you’d call self.trader.place_market_order(...) if real.
        import random
        result = round(random.uniform(-tp/2, tp), 2)

        # update session stats
        self.total_pnl    += result
        self.total_trades += 1
        if result > 0:
            self.wins += 1

        # update UI vars
        self.pnl_var.set(f"{self.total_pnl:.2f}")
        self.trades_var.set(str(self.total_trades))
        win_rate = (int(self.wins / self.total_trades * 100)
                    if self.total_trades else 0)
        self.win_rate_var.set(f"{win_rate}%")

        self._log(f"Result: {result:+.2f} pips | Total P&L: {self.total_pnl:+.2f}")

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.output.configure(state="normal")
        self.output.insert("end", f"[{ts}] {msg}\n")
        self.output.see("end")
        self.output.configure(state="disabled")


if __name__ == "__main__":
    import settings
    app = MainApplication(settings.Settings.load())
    app.mainloop()

# -*- coding: utf-8 -*-
"""
SM2数字签名与验签系统 — tkinter GUI (现代化风格)
使用 ttk.Style + clam 主题定制，无需额外依赖
"""

import ctypes
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import base64

# ── Windows 高 DPI 适配：解决字体模糊 ──
if sys.platform == 'win32':
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PerMonitorV2
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

from src.sm3 import sm3_hash_hex
from src.sm2 import (
    generate_keypair,
    sm2_sign,
    sm2_verify,
    privkey_to_pubkey,
)

# ═══════════════════════════════════════════════════════════
# 现代化配色方案
# ═══════════════════════════════════════════════════════════

_COLORS = {
    'bg':           '#F0F2F5',   # 主背景
    'card':         '#FFFFFF',   # 卡片/面板背景
    'text':         '#1A1A2E',   # 主文字
    'text_secondary': '#6B7280', # 次要文字
    'primary':      '#4F46E5',   # 主按钮色 (靛蓝)
    'primary_hover':'#4338CA',   # 主按钮悬停
    'success':      '#059669',   # 成功绿
    'danger':       '#DC2626',   # 失败红
    'border':       '#E5E7EB',   # 边框
    'input_bg':     '#F9FAFB',   # 输入框背景
    'input_focus':  '#EEF2FF',   # 输入框焦点
    'accent':       '#818CF8',   # 强调色
}


def _apply_theme(root: tk.Tk):
    """应用自定义 ttk 主题"""
    style = ttk.Style(root)
    style.theme_use('clam')

    # 配置全局字体
    root.option_add('*Font', ('Microsoft YaHei', 10))

    # ── 框架样式 ──
    style.configure('Card.TFrame', background=_COLORS['card'],
                    relief='solid', borderwidth=1)
    style.configure('Main.TFrame', background=_COLORS['bg'])

    # ── LabelFrame 样式 ──
    style.configure('Card.TLabelframe', background=_COLORS['card'],
                    relief='solid', borderwidth=1)
    style.configure('Card.TLabelframe.Label',
                    background=_COLORS['card'],
                    foreground=_COLORS['text'],
                    font=('Microsoft YaHei', 10, 'bold'))

    # ── 标签 ──
    style.configure('Title.TLabel', font=('Microsoft YaHei', 20, 'bold'),
                    foreground=_COLORS['text'], background=_COLORS['bg'])
    style.configure('Subtitle.TLabel', font=('Microsoft YaHei', 10),
                    foreground=_COLORS['text_secondary'], background=_COLORS['bg'])
    style.configure('Hint.TLabel', font=('Microsoft YaHei', 10),
                    foreground=_COLORS['text_secondary'],
                    background=_COLORS['card'])
    style.configure('FieldLabel.TLabel', font=('Microsoft YaHei', 10),
                    foreground=_COLORS['text'], background=_COLORS['card'])
    style.configure('Success.TLabel', font=('Microsoft YaHei', 11, 'bold'),
                    foreground=_COLORS['success'], background=_COLORS['card'])
    style.configure('Danger.TLabel', font=('Microsoft YaHei', 11, 'bold'),
                    foreground=_COLORS['danger'], background=_COLORS['card'])

    # ── 按钮 ──
    style.configure('Primary.TButton',
                    font=('Microsoft YaHei', 10, 'bold'),
                    background=_COLORS['primary'],
                    foreground='white',
                    borderwidth=0,
                    padding=(16, 8))
    style.map('Primary.TButton',
              background=[('active', _COLORS['primary_hover']),
                          ('!disabled', _COLORS['primary'])],
              foreground=[('active', 'white'), ('!disabled', 'white')])

    style.configure('Secondary.TButton',
                    font=('Microsoft YaHei', 10),
                    padding=(14, 6))

    # ── 输入框 ──
    style.configure('Modern.TEntry',
                    fieldbackground=_COLORS['input_bg'],
                    borderwidth=1,
                    relief='solid',
                    padding=6)
    style.map('Modern.TEntry',
              fieldbackground=[('focus', _COLORS['input_focus'])])

    # ── 单选按钮 ──
    style.configure('Modern.TRadiobutton',
                    background=_COLORS['card'],
                    foreground=_COLORS['text'],
                    font=('Microsoft YaHei', 10))

    # ── 滚动条（现代扁平风格，无箭头，窄条）──
    style.configure('Vertical.TScrollbar',
                    background=_COLORS['card'],
                    troughcolor=_COLORS['bg'],
                    borderwidth=0,
                    arrowsize=0,
                    width=6)
    style.map('Vertical.TScrollbar',
              background=[('active', _COLORS['card']),
                          ('!active', _COLORS['card'])],
              troughcolor=[('!active', _COLORS['bg'])])

    # ── 状态栏 ──
    style.configure('Status.TLabel',
                    font=('Microsoft YaHei', 10),
                    foreground=_COLORS['text_secondary'],
                    background=_COLORS['card'],
                    padding=(12, 4))


class _IconButton(tk.Canvas):
    """圆角按钮 (Canvas 实现，用于主要操作按钮)"""

    def __init__(self, parent, text, command, width=120, height=38,
                 fill=_COLORS['primary'], hover_fill=_COLORS['primary_hover']):
        super().__init__(parent, width=width, height=height,
                         highlightthickness=0, bg=_COLORS['card'])
        self._fill = fill
        self._hover_fill = hover_fill
        self._command = command
        self._text = text

        self._draw(fill)
        self.bind('<Button-1>', lambda _: command())
        self.bind('<Enter>', lambda _: self._draw(hover_fill))
        self.bind('<Leave>', lambda _: self._draw(fill))

    def _draw(self, fill_color):
        self.delete('all')
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        radius = 8
        self._draw_rounded_rect(0, 0, w, h, radius,
                                fill=fill_color, outline=fill_color)
        self.create_text(w // 2, h // 2, text=self._text,
                         fill='white', font=('Microsoft YaHei', 10, 'bold'))

    def _draw_rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        """绘制圆角矩形"""
        points = [
            x1 + r, y1, x2 - r, y1,
            x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2,
            x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r,
            x1, y1 + r, x1, y1,
        ]
        self.create_polygon(points, smooth=True, **kwargs)


class SM2SignatureApp:
    """SM2 签名验签系统 — 现代化主窗口"""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('SM2 数字签名与验签系统')
        self.root.geometry('960x1080')
        self.root.minsize(640, 620)
        self.root.configure(bg=_COLORS['bg'])

        _apply_theme(root)

        self._priv_key = ''
        self._pub_key = ''

        self._build_ui()

    # ── UI 构建 ──────────────────────────────────────────

    def _build_ui(self):
        # 顶部标题栏
        header = tk.Frame(self.root, bg=_COLORS['bg'])
        header.pack(fill=tk.X, padx=24, pady=(20, 12))
        ttk.Label(header, text='SM2 数字签名与验签系统',
                  style='Title.TLabel').pack(anchor=tk.W)
        ttk.Label(header, text='基于国密 SM2/SM3 算法 · 自主实现',
                  style='Subtitle.TLabel').pack(anchor=tk.W, pady=(2, 0))

        # 滚动内容区
        self._canvas = tk.Canvas(self.root, bg=_COLORS['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL,
                                  command=self._canvas.yview,
                                  style='Vertical.TScrollbar')
        content = tk.Frame(self._canvas, bg=_COLORS['bg'])

        content.bind('<Configure>', lambda _: self._canvas.configure(
            scrollregion=self._canvas.bbox('all')))
        self._canvas.create_window((0, 0), window=content, anchor=tk.NW, tags='content')
        self._canvas.configure(yscrollcommand=scrollbar.set)

        def _on_canvas_resize(event):
            self._canvas.itemconfig('content', width=event.width)

        self._canvas.bind('<Configure>', _on_canvas_resize)

        # 全局鼠标滚轮 — 绑定到根窗口 + Canvas，整个窗口任意位置都可滚动
        self._canvas.bind('<MouseWheel>', self._on_mousewheel)
        self.root.bind('<MouseWheel>', self._on_mousewheel)

        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                          padx=(24, 0), pady=(0, 24))
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 20), pady=(0, 24))

        self._content = content

        # 各个功能卡片
        self._build_key_card()
        self._build_message_card()
        self._build_sign_card()
        self._build_verify_card()

        # 状态栏
        self._build_status_bar()

    def _make_card(self, title: str, row: int) -> ttk.LabelFrame:
        """创建统一样式的卡片"""
        card = ttk.LabelFrame(self._content, text=f'  {title}  ',
                              style='Card.TLabelframe', padding=16)
        card.grid(row=row, column=0, sticky='ew', pady=(0, 12))
        card.columnconfigure(0, weight=1)
        return card

    # ── 密钥卡片 ──────────────────────────────────────────

    def _build_key_card(self):
        card = self._make_card('密钥管理', 0)

        # 按钮行
        btn_row = tk.Frame(card, bg=_COLORS['card'])
        btn_row.grid(row=0, column=0, sticky='w')
        _IconButton(btn_row, text='生成密钥对',
                    command=self._on_gen_keypair).pack(side=tk.LEFT)

        ttk.Label(btn_row, text='  生成 SM2 椭圆曲线密钥对 (私钥 256-bit)',
                  style='Hint.TLabel').pack(side=tk.LEFT, padx=8)

        # 私钥
        ttk.Label(card, text='私钥 (hex)', style='FieldLabel.TLabel').grid(
            row=1, column=0, sticky='w', pady=(16, 4))
        self._priv_var = tk.StringVar()
        priv_entry = ttk.Entry(card, textvariable=self._priv_var,
                               font=('Consolas', 10), state='readonly')
        priv_entry.grid(row=2, column=0, sticky='ew', ipady=2)

        # 公钥
        ttk.Label(card, text='公钥 (hex, 04‖x‖y)', style='FieldLabel.TLabel').grid(
            row=3, column=0, sticky='w', pady=(12, 4))
        self._pub_var = tk.StringVar()
        pub_entry = ttk.Entry(card, textvariable=self._pub_var,
                              font=('Consolas', 10), state='readonly')
        pub_entry.grid(row=4, column=0, sticky='ew', ipady=2)

    # ── 消息卡片 ──────────────────────────────────────────

    def _build_message_card(self):
        card = self._make_card('消息输入', 1)

        # 文本域
        text_frame = tk.Frame(card, bg=_COLORS['border'], padx=1, pady=1)
        text_frame.grid(row=0, column=0, sticky='nsew', pady=(0, 10))
        card.rowconfigure(0, weight=1)

        self._msg_text = tk.Text(
            text_frame, height=4, font=('Consolas', 11),
            bg=_COLORS['input_bg'], fg=_COLORS['text'],
            relief='flat', borderwidth=0,
            insertbackground=_COLORS['primary'],
            selectbackground=_COLORS['accent'],
            selectforeground='white',
            padx=10, pady=8,
        )
        self._msg_text.pack(fill=tk.BOTH, expand=True)

        # 格式选择
        fmt_row = tk.Frame(card, bg=_COLORS['card'])
        fmt_row.grid(row=1, column=0, sticky='w')

        ttk.Label(fmt_row, text='输入格式', style='FieldLabel.TLabel').pack(
            side=tk.LEFT, padx=(0, 12))

        self._fmt_var = tk.StringVar(value='text')
        for val, label in [('text', '普通文本'), ('base64', 'Base64'), ('hex', 'Hex')]:
            ttk.Radiobutton(
                fmt_row, text=label, variable=self._fmt_var, value=val,
                style='Modern.TRadiobutton'
            ).pack(side=tk.LEFT, padx=(0, 16))

    # ── 签名卡片 ──────────────────────────────────────────

    def _build_sign_card(self):
        card = self._make_card('签名操作', 2)

        btn_row = tk.Frame(card, bg=_COLORS['card'])
        btn_row.grid(row=0, column=0, sticky='w')
        _IconButton(btn_row, text='执行签名',
                    command=self._on_sign).pack(side=tk.LEFT)

        ttk.Label(btn_row, text='  使用 SM3 哈希 + SM2 签名，输出 r‖s',
                  style='Hint.TLabel').pack(side=tk.LEFT, padx=8)

        ttk.Label(card, text='签名结果 (r‖s, hex)', style='FieldLabel.TLabel').grid(
            row=1, column=0, sticky='w', pady=(16, 4))
        self._sig_var = tk.StringVar()
        sig_entry = ttk.Entry(card, textvariable=self._sig_var,
                              font=('Consolas', 10), state='readonly')
        sig_entry.grid(row=2, column=0, sticky='ew', ipady=2)

    # ── 验签卡片 ──────────────────────────────────────────

    def _build_verify_card(self):
        card = self._make_card('验签操作', 3)
        card.rowconfigure(0, weight=0)

        # 签名输入
        ttk.Label(card, text='签名 (hex, r‖s)', style='FieldLabel.TLabel').grid(
            row=0, column=0, sticky='w')
        self._verify_sig_var = tk.StringVar()
        ttk.Entry(card, textvariable=self._verify_sig_var,
                  font=('Consolas', 10)).grid(
            row=1, column=0, sticky='ew', pady=(4, 10), ipady=2)

        # 公钥输入
        ttk.Label(card, text='公钥 (hex, 04‖x‖y)', style='FieldLabel.TLabel').grid(
            row=2, column=0, sticky='w')
        self._verify_pub_var = tk.StringVar()
        ttk.Entry(card, textvariable=self._verify_pub_var,
                  font=('Consolas', 10)).grid(
            row=3, column=0, sticky='ew', pady=(4, 14), ipady=2)

        # 按钮 + 结果
        bottom_row = tk.Frame(card, bg=_COLORS['card'])
        bottom_row.grid(row=4, column=0, sticky='ew')

        _IconButton(bottom_row, text='验证签名',
                    command=self._on_verify,
                    fill=_COLORS['success'],
                    hover_fill='#047857').pack(side=tk.LEFT)

        self._verify_result_var = tk.StringVar()
        self._verify_result_label = ttk.Label(
            bottom_row, textvariable=self._verify_result_var,
            style='Success.TLabel')
        self._verify_result_label.pack(side=tk.LEFT, padx=16)

    # ── 状态栏 ──────────────────────────────────────────

    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=_COLORS['card'], height=32)
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        bar.pack_propagate(False)

        # 左侧圆点指示器
        self._status_dot = tk.Canvas(bar, width=8, height=8,
                                     bg=_COLORS['card'], highlightthickness=0)
        self._status_dot.pack(side=tk.LEFT, padx=(16, 6))
        self._dot = self._status_dot.create_oval(
            0, 0, 8, 8, fill=_COLORS['text_secondary'], outline='')

        self._status_var = tk.StringVar(value='就绪')
        ttk.Label(bar, textvariable=self._status_var,
                  style='Status.TLabel').pack(side=tk.LEFT)

    # ── 消息解析 ──────────────────────────────────────────

    def _on_mousewheel(self, event):
        """全局鼠标滚轮 — 滚动内容区"""
        self._canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')

    def _parse_message(self) -> bytes:
        raw = self._msg_text.get('1.0', 'end-1c')
        fmt = self._fmt_var.get()

        if fmt == 'text':
            return raw.encode('utf-8')
        elif fmt == 'base64':
            try:
                return base64.b64decode(raw)
            except Exception:
                raise ValueError('Base64 解码失败，请检查输入')
        elif fmt == 'hex':
            try:
                return bytes.fromhex(raw.replace(' ', '').replace('\n', ''))
            except Exception:
                raise ValueError('Hex 解码失败，请检查输入')
        else:
            raise ValueError(f'未知格式: {fmt}')

    # ── 事件处理 ──────────────────────────────────────────

    def _on_gen_keypair(self):
        try:
            priv_hex, pub_hex = generate_keypair()
            self._priv_key = priv_hex
            self._pub_key = pub_hex
            self._priv_var.set(priv_hex)
            self._pub_var.set(pub_hex)
            self._verify_pub_var.set(pub_hex)
            self._set_status('密钥对生成成功', 'success')
        except Exception as e:
            messagebox.showerror('错误', f'密钥生成失败:\n{e}')
            self._set_status('密钥生成失败', 'error')

    def _on_sign(self):
        if not self._priv_key:
            messagebox.showwarning('提示', '请先生成密钥对')
            return

        try:
            msg_bytes = self._parse_message()
        except ValueError as e:
            messagebox.showerror('输入错误', str(e))
            self._set_status('签名失败：消息格式错误', 'error')
            return

        try:
            sig = sm2_sign(msg_bytes, self._priv_key, self._pub_key)
            self._sig_var.set(sig)
            self._verify_sig_var.set(sig)
            self._set_status(
                f'签名成功 — SM3 杂凑值: {sm3_hash_hex(msg_bytes)[:16]}...',
                'success')
        except Exception as e:
            messagebox.showerror('错误', f'签名失败:\n{e}')
            self._set_status('签名失败', 'error')

    def _on_verify(self):
        sig_hex = self._verify_sig_var.get().strip()
        pub_hex = self._verify_pub_var.get().strip()

        if not sig_hex or not pub_hex:
            messagebox.showwarning('提示', '请填写签名和公钥')
            return

        try:
            msg_bytes = self._parse_message()
        except ValueError as e:
            messagebox.showerror('输入错误', str(e))
            self._set_status('验签失败：消息格式错误', 'error')
            return

        try:
            ok = sm2_verify(msg_bytes, sig_hex, pub_hex)
            if ok:
                self._verify_result_var.set('验证成功')
                self._verify_result_label.configure(style='Success.TLabel')
                self._set_status('验签通过 — 签名有效', 'success')
            else:
                self._verify_result_var.set('验证失败')
                self._verify_result_label.configure(style='Danger.TLabel')
                self._set_status('验签未通过 — 签名无效', 'error')
        except Exception as e:
            messagebox.showerror('错误', f'验签异常:\n{e}')
            self._verify_result_var.set('')
            self._set_status('验签异常', 'error')

    def _set_status(self, msg: str, level: str = 'info'):
        self._status_var.set(msg)
        colors = {
            'success': _COLORS['success'],
            'error': _COLORS['danger'],
            'info': _COLORS['text_secondary'],
        }
        self._status_dot.itemconfig(self._dot, fill=colors.get(level, colors['info']))


# ═══════════════════════════════════════════════════════════
# 程序入口
# ═══════════════════════════════════════════════════════════

def main():
    root = tk.Tk()
    SM2SignatureApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()

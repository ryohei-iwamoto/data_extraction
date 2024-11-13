import tkinter as tk
from tkinter import ttk
from request_handler import send_request, generate_code
from utilities import extract_header_info, extract_payload_info

def setup_ui(window, config_manager):
    url_frame = tk.Frame(window)
    url_frame.pack(fill='x', pady=10, padx=10)

    url_label = tk.Label(url_frame, text="URL")
    url_label.pack(side='left')

    url_entry = tk.Entry(url_frame, width=70)
    url_entry.pack(side='left', fill='x', expand=True)

    http_methods = ['GET', 'POST', 'PUT']
    method_var = tk.StringVar(window)
    method_var.set(http_methods[0]) 

    method_dropdown = ttk.Combobox(url_frame, textvariable=method_var, values=http_methods)
    method_dropdown.pack(side='left')

    tab_control_input = ttk.Notebook(window)

    header_tab = ttk.Frame(tab_control_input)
    tab_control_input.add(header_tab, text='Header(ヘッダー)')

    payload_tab = ttk.Frame(tab_control_input)
    tab_control_input.add(payload_tab, text='Payload(ペイロード)')

    header_text = tk.Text(header_tab, width=50, height=15)
    header_text.pack(padx=10, pady=10, fill='both', expand=True)

    payload_text = tk.Text(payload_tab, width=50, height=15)
    payload_text.pack(padx=10, pady=10, fill='both', expand=True)

    tab_control_input.pack(expand=1, fill='both')

    tab_control_output = ttk.Notebook(window)

    code_tab = ttk.Frame(tab_control_output)
    tab_control_output.add(code_tab, text='生成されたコード')

    response_tab = ttk.Frame(tab_control_output)
    tab_control_output.add(response_tab, text='レスポンス')

    code_text = tk.Text(code_tab, width=50, height=15)
    code_text.pack(padx=10, pady=10, fill='both', expand=True)

    response_text = tk.Text(response_tab, width=50, height=15)
    response_text.pack(padx=10, pady=10, fill='both', expand=True)

    tab_control_output.pack(expand=1, fill='both')

    generate_button = tk.Button(window, text="コードを生成する", command=lambda: generate_code(method_var.get(), url_entry.get(), extract_header_info(header_text.get("1.0", tk.END)), extract_payload_info(payload_text.get("1.0", tk.END))))
    generate_button.pack(pady=10, padx=(5,0), side='left')

    send_request_button = tk.Button(window, text="リクエストを送信する", command=lambda: send_request(method_var.get(), url_entry.get(), extract_header_info(header_text.get("1.0", tk.END)), extract_payload_info(payload_text.get("1.0", tk.END))))
    send_request_button.pack(pady=10, padx=(0,5), side='right')

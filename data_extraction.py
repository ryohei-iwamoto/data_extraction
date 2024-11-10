import tkinter as tk
from tkinter import ttk
import tkinter.messagebox
import requests
import json
from io import BytesIO
import webbrowser
import tempfile
from html.parser import HTMLParser
import re
import configparser

config = configparser.ConfigParser()
config.read('config.txt')
headers_of_interest = [
                    "cookie",
                    "user-agent", 
                    "Set-Cookie",
                    "referer",
                    "set-cookie",
                    ]

headers_of_not_interest = [
                    ":authority",
                    ":method",
                    ":path",
                    ":scheme",
                    ]


def on_text_change(event):
    header_content = header_text.get("1.0", tk.END).strip()
    add_header_interest(header_content)

class HTMLChecker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.is_html = False

    def handle_starttag(self, tag, attrs):
        self.is_html = True

def extract_header_info(header_text):
    header_info = {}
    for header in headers_of_interest:
        pattern = re.compile(f"{header}\s*:\s*(.*)", re.IGNORECASE)
        match = pattern.search(header_text)
        if match:
            header_info[header] = match.group(1).strip()
    return header_info

def extract_payload_info(payload_text):
    payload_info = {}
    for line in payload_text.split("\n"):
        if ": " in line:
            key, value = line.split(": ", 1)
            payload_info[key] = value
    return payload_info


def add_header_interest(header_text):
    lines = header_text.split("\n")
    for i in range(len(lines)):
        line = lines[i].strip()
        if line.endswith(":"):
            header_name = line[:-1]
            if header_name not in (header for header in headers_of_not_interest):
                headers_of_interest.append(header_name)


def extract_all_headers(header_text):
    headers = []
    lines = header_text.split("\n")
    for i in range(len(lines)):
        line = lines[i].strip()
        if line.endswith(":"): 
            header_name = line[:-1]
            headers.append(header_name)
    return headers

def clear_response():
    response_text.delete("1.0", tk.END)


def copy_code():
    window.clipboard_clear()
    window.clipboard_append(code_text.get("1.0", tk.END))

def load_config():
    global config
    config.read('config.txt')
    stay_on_top = config.get('Settings', 'StayOnTop', fallback='no')
    if stay_on_top.lower() == 'yes':
        window.attributes('-topmost', 1)
        stay_on_top_var.set(True)
    else:
        window.attributes('-topmost', 0)
        stay_on_top_var.set(False)

def save_config():
    config['Settings'] = {}
    config['Settings']['StayOnTop'] = 'yes' if stay_on_top_var.get() else 'no'
    with open('config.txt', 'w') as f:
        config.write(f)

def toggle_stay_on_top():
    if stay_on_top_var.get():
        window.attributes('-topmost', 1)
    else:
        window.attributes('-topmost', 0)
    save_config()

def send_request():
    try:
        header = extract_header_info(header_text.get("1.0", tk.END).strip())
        payload = extract_payload_info(payload_text.get("1.0", tk.END).strip())
        url = url_entry.get() or header.get("url", "YOUR_URL")
        method = method_var.get().lower()
        request_method = getattr(requests, method, None)
        if request_method:
            response = request_method(url,         headers=header, data=payload)
            response_text.delete("1.0", tk.END)
            if response.headers.get("Content-Type", "").startswith("text/html"):
                checker = HTMLChecker()
                checker.feed(response.text)
                if checker.is_html:
                    temp_file = tempfile.NamedTemporaryFile(suffix=".html", delete=False)
                    temp_file.write(response.content)
                    temp_file.close()
                    webbrowser.open('file://' + temp_file.name)
                    response_text.insert(tk.END, response.text)
                else:
                    response_text.insert(tk.END, response.text)
            else:
                response_text.insert(tk.END, response.text)
        else:
            response_text.delete("1.0", tk.END)
            response_text.insert(tk.END, "Unsupported method: " + method)
    except Exception as e:
        print(e)
        tk.messagebox.showerror("エラー", str(e))


def generate_code():
    header = extract_header_info(header_text.get("1.0", tk.END).strip())
    payload = extract_payload_info(payload_text.get("1.0", tk.END).strip())
    url = url_entry.get() or header.get("url", "URLを入れてください")
    method = method_var.get().lower()
    code = f'''
import requests

url = "{url}"

headers = {json.dumps(header, indent=4)}

payload = {json.dumps(payload, indent=4)}

response = requests.{method}(url, headers=headers, params=payload)

print(response.text)
            '''
    
    code_text.delete("1.0", tk.END)
    code_text.insert(tk.END, code)


def open_dialog():
    all_headers = extract_all_headers(header_text.get("1.0", tk.END).strip())
    
    dialog = tk.Toplevel(window)
    if stay_on_top_var.get():
        dialog.attributes("-topmost", True)
    else:
        dialog.attributes("-topmost", False)
    
    dialog.title("含める情報を選択")
    dialog.geometry("450x600")

    container = tk.Frame(dialog)
    container.pack(fill='both', expand=True)
    
    canvas = tk.Canvas(container)

    def on_canvas_scroll(event):
        canvas.yview_scroll(-1 * (event.delta // 120), "units")

    scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

    canvas.bind("<MouseWheel>", on_canvas_scroll)
    scrollable_frame.bind("<MouseWheel>", on_canvas_scroll)

    header_vars = {header: tk.BooleanVar() for header in all_headers}

    for i, header in enumerate(all_headers):
        checkbutton = tk.Checkbutton(scrollable_frame, text=header, variable=header_vars[header])
        checkbutton.grid(row=i, sticky='w')
        checkbutton.bind("<MouseWheel>", on_canvas_scroll)
        if header in [h for h in headers_of_interest]:
            checkbutton.select()

    def update_headers():
        headers_of_interest.clear()
        for header, var in header_vars.items():
            if var.get():
                headers_of_interest.append(header)
        dialog.destroy()

    def select_all():
        for var in header_vars.values():
            var.set(True)

    def deselect_all():
        for var in header_vars.values():
            var.set(False)

    select_all_button = tk.Button(scrollable_frame, text="全選択", command=select_all)
    select_all_button.grid(row=len(all_headers) + 2, column=0, padx=(5, 0))

    deselect_all_button = tk.Button(scrollable_frame, text="全選択解除", command=deselect_all)
    deselect_all_button.grid(row=len(all_headers) + 2, column=1, padx=(5, 0))

    ok_button = tk.Button(scrollable_frame, text="OK", command=update_headers)
    ok_button.grid(row=len(all_headers) + 2, column=2, padx=(5, 0))

    scrollable_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))
    canvas.config(yscrollcommand=scrollbar.set)


window = tk.Tk()
window.title("データちゅるちゅる")
window.geometry("800x600")

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
header_text.bind("<KeyRelease>", on_text_change)
header_text.bind("<ButtonRelease-1>", on_text_change)
header_text.bind("<ButtonRelease-2>", on_text_change)

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


##########################################
# 下部ボタン
##########################################
generate_button = tk.Button(window, text="コードを生成する", command=generate_code)
generate_button.pack(pady=10, padx=(5,0), side='left')

copy_button = tk.Button(window, text="コピー", command=copy_code)
copy_button.pack(pady=10, padx=(5,0), side='left')

dialog_button = tk.Button(window, text="ヘッダを選択", command=open_dialog)
dialog_button.pack(pady=10, padx=(5,0), side='left')

stay_on_top_var = tk.BooleanVar()  # 常に最前面に表示するかどうか
stay_on_top_check = tk.Checkbutton(window, text="常に最前面に表示", variable=stay_on_top_var, command=toggle_stay_on_top)
stay_on_top_check.pack(pady=10, padx=(160,0), side='left')

clear_button = tk.Button(window, text="クリア", command=clear_response)
clear_button.pack(pady=10, padx=(0,5), side='right')

send_request_button = tk.Button(window, text="リクエストを送信する", command=send_request)
send_request_button.pack(pady=10, padx=(0,5), side='right')


load_config()
window.mainloop()

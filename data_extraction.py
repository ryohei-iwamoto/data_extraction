import tkinter as tk
from tkinter import ttk
import tkinter.messagebox
import requests
import json
import tempfile
import webbrowser
from html.parser import HTMLParser
import re
import configparser

# 設定ファイルの読み込み
config = configparser.ConfigParser()
config.read('config.txt')

# 初期に省くヘッダー要素等
headers_of_interest = ["cookie", "user-agent", "Set-Cookie", "referer", "set-cookie"]
headers_of_not_interest = [":authority", ":method", ":path", ":scheme"]

# ヘッダーテキストの変更時の処理
def on_text_change(event):
    add_header_interest(header_text.get("1.0", tk.END).strip())

# HTMLコンテンツかどうかをチェックするクラス
class HTMLChecker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.is_html = False

    def handle_starttag(self, tag, attrs):
        self.is_html = True

# ヘッダー情報の抽出
def extract_header_info(header_text):
    header_info = {}
    for header in headers_of_interest:
        pattern = re.compile(f"{header}\s*:\s*(.*)", re.IGNORECASE)
        match = pattern.search(header_text)
        if match:
            header_info[header] = match.group(1).strip()
    return header_info

# ペイロード情報の抽出
def extract_payload_info(payload_text):
    payload_info = {}
    for line in payload_text.split("\n"):
        if ": " in line:
            key, value = line.split(": ", 1)
            payload_info[key] = value
    return payload_info

# ヘッダーの追加
def add_header_interest(header_text):
    lines = header_text.split("\n")
    for line in lines:
        header_name = line.strip().rstrip(":")
        if header_name and header_name not in headers_of_not_interest:
            headers_of_interest.append(header_name)

# レスポンス領域のクリア
def clear_response():
    response_text.delete("1.0", tk.END)

# コードのコピー
def copy_code():
    window.clipboard_clear()
    window.clipboard_append(code_text.get("1.0", tk.END))

# 設定の読み込み
def load_config():
    stay_on_top = config.get('Settings', 'StayOnTop', fallback='no').lower()
    stay_on_top_var.set(stay_on_top == 'yes')
    window.attributes('-topmost', 1 if stay_on_top == 'yes' else 0)

# 設定の保存
def save_config():
    config['Settings'] = {'StayOnTop': 'yes' if stay_on_top_var.get() else 'no'}
    with open('config.txt', 'w') as f:
        config.write(f)

# 常に最前面に表示の切り替え
def toggle_stay_on_top():
    window.attributes('-topmost', 1 if stay_on_top_var.get() else 0)
    save_config()

# リクエストの送信
def send_request():
    try:
        headers = extract_header_info(header_text.get("1.0", tk.END).strip())
        payload = extract_payload_info(payload_text.get("1.0", tk.END).strip())
        url = url_entry.get() or headers.get("url", "YOUR_URL")
        method = method_var.get().lower()
        response = getattr(requests, method, None)(url, headers=headers, data=payload)
        response_text.delete("1.0", tk.END)
        response_text.insert(tk.END, response.text)
    except Exception as e:
        tk.messagebox.showerror("エラー", str(e))

# コードの生成
def generate_code():
    headers = extract_header_info(header_text.get("1.0", tk.END).strip())
    payload = extract_payload_info(payload_text.get("1.0", tk.END).strip())
    url = url_entry.get() or headers.get("url", "URLを入れてください")
    method = method_var.get().lower()
    code = f'''
import requests

url = "{url}"

headers = {json.dumps(headers, indent=4)}

payload = {json.dumps(payload, indent=4)}

response = requests.{method}(url, headers=headers, params=payload)

print(response.text)
    '''
    code_text.delete("1.0", tk.END)
    code_text.insert(tk.END, code)






# GUI部分の定義（ウィンドウ、ラベル、ボタンなど）
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

generate_button = tk.Button(window, text="コードを生成する", command=generate_code)
generate_button.pack(pady=10, padx=(5,0), side='left')

copy_button = tk.Button(window, text="コピー", command=copy_code)
copy_button.pack(pady=10, padx=(5,0), side='left')

clear_button = tk.Button(window, text="クリア", command=clear_response)
clear_button.pack(pady=10, padx=(0,5), side='right')

send_request_button = tk.Button(window, text="リクエストを送信する", command=send_request)
send_request_button.pack(pady=10, padx=(0,5), side='right')

stay_on_top_var = tk.BooleanVar()
stay_on_top_check = tk.Checkbutton(window, text="常に最前面に表示", variable=stay_on_top_var, command=toggle_stay_on_top)
stay_on_top_check.pack(pady=10, padx=(160,0), side='left')

load_config()
window.mainloop()

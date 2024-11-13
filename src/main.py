import tkinter as tk
from ui_elements import setup_ui
from config_manager import ConfigManager

def main():
    window = tk.Tk()
    window.title("データちゅるちゅる")
    window.geometry("800x600")

    config_manager = ConfigManager('config.txt')
    setup_ui(window, config_manager)

    window.mainloop()

if __name__ == "__main__":
    main()

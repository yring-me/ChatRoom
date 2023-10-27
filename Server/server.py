import tkinter as tk
import socket
import time
import tkinter.messagebox

import ttkbootstrap as ttk
from ttkbootstrap.scrolled import ScrolledText
import threading
from utils import *


class LoginWindow:
    def __init__(self):
        self.aes = None
        self.rsa = None
        self.encrypt_input = ''
        self.share_key = None
        self.wait_text = None
        self.wait_window = None
        self.server = None
        self.btn_send = None
        self.Text_encrypt = None
        self.save_height = 1000
        self.save_width = 800
        self.Text_aes = None
        self.Text_input = None
        self.frm_chat_input = None
        self.frm_chat_encrypt = None
        self.frm_chat_history = None
        self.chat_window = None
        self.IP = None
        self.PORT = None
        self.login_window = None
        self.IP_var = None
        self.PORT_var = None
        self.line = 0
        self.Text_history = None
        self.chat_window_first_load = 0
        self.start = 1.0
        self.end = 1.0
        self.client_socket = None
        self.client_addr = None

    def draw_login_window(self):
        self.login_window = ttk.Window()
        self.login_window.title('ChatRoom-Login')

        self.login_window.geometry("700x400")
        self.login_window.resizable(True, True)

        login_banner = ttk.PhotoImage(file='Welcome.gif')
        imgLabel = ttk.Label(self.login_window, image=login_banner)
        imgLabel.place(x=150, y=20)
        # 标签 用户密码
        Label_IP = ttk.Label(self.login_window, text="IP：")
        Label_PORT = ttk.Label(self.login_window, text="PORT：")
        Label_IP.place(x=200, y=200)
        Label_PORT.place(x=200, y=240)
        self.IP_var = ttk.StringVar()
        self.PORT_var = ttk.StringVar()

        entry_ip = ttk.Entry(self.login_window, textvariable=self.IP_var)
        entry_ip.place(x=260, y=200)
        entry_ip.focus_force()

        entry_port = ttk.Entry(self.login_window, textvariable=self.PORT_var)
        entry_port.place(x=260, y=240)

        bt_login = ttk.Button(self.login_window, text="登录(Login)")
        bt_login.bind("<Button-1>", self.usr_login)
        entry_port.bind_all('<Return>', self.usr_login)

        bt_login.place(x=300, y=300)

        self.login_window.mainloop()

    def usr_login(self, event):

        IP = self.IP_var.get()
        PORT = self.PORT_var.get()
        self.IP = IP
        self.PORT = PORT
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind((IP, int(PORT)))
            self.server.listen(1)

        except Exception as e:
            tk.messagebox.showerror('server failed!')
            exit()

        self.login_window.update()
        self.login_window.withdraw()
        self.run()
        self.draw_chat_window()

    def draw_chat_window(self):
        self.chat_window = ttk.Window(themename='darkly', resizable=(1000, 800))
        self.chat_window.title('ChatRoom-Server')

        self.chat_window.geometry('1000x800')

        self.draw_chat_encrypt()
        self.draw_chat_history()
        self.draw_chat_input()

        self.chat_window.bind('<Configure>', self.resize)

        self.chat_window.mainloop()

    def resize(self, event):

        new_width = self.chat_window.winfo_width()
        new_height = self.chat_window.winfo_height()

        if new_width == 1 and new_height == 1:
            return
        if self.save_width != new_width or self.save_height != new_height:
            input_ = self.get_input()
            self.Text_encrypt.delete("0.0", ttk.END)
            n = new_height // 40
            self.Text_encrypt.insert('1.0', 'RSA\n')
            self.Text_encrypt.insert('2.0', 'N:{}\n'.format(self.rsa.n))
            self.Text_encrypt.insert('3.0', 'D:{}\n'.format(self.rsa.d))

            self.Text_encrypt.insert('4.0', '\n' * n)
            self.Text_encrypt.insert('{}.0'.format(n), 'AES\n')
            self.Text_encrypt.insert('{}.0'.format(n+1), 'PLAIN_TEXT:{}\n'.format(input_))
            self.Text_encrypt.insert('{}.0'.format(n+2), 'ENCRYPT_TEXT:{}\n'.format(self.encrypt_input))

            # button1.place(x=20, y=new_height - 40)
        self.save_width = new_width
        self.save_height = new_height

    def draw_chat_input(self):
        ttk.Style().configure(style='send.TButton', font=('Helvetica', 12), background='yellow', width=12)
        self.btn_send = ttk.Button(self.chat_window, text='send', style='send.TButton')
        self.btn_send.bind("<Button-1>", self.send_msg)
        self.btn_send.pack(side=ttk.TOP, anchor='ne')
        # btn_send.pack()
        self.Text_input = ScrolledText(self.chat_window, width=76, height=14, autohide=True)
        self.Text_input.pack(side=ttk.TOP, expand=ttk.YES, fill=ttk.BOTH)

        self.Text_input.focus_get()
        self.Text_input.bind_all('<Return>', self.send_msg)
        self.Text_input.bind_all('<Shift_R>', lambda x: self.Text_input.unbind_all('<Return>'))
        self.Text_input.bind_all('<Shift_L>', lambda x: self.Text_input.bind_all('<Return>', self.send_msg))

    def draw_chat_history(self):
        # ttk.Style().configure(style='history.T', font=('Helvetica', 12), foreground='green',width=12)

        self.Text_history = ScrolledText(self.chat_window, width=76, height=34, autohide=True, foreground='green')

        self.Text_history.pack(side=ttk.TOP, expand=ttk.YES, fill=ttk.BOTH)

    def draw_chat_encrypt(self):
        self.Text_encrypt = ScrolledText(self.chat_window, width=32, height=25, autohide=True)
        self.Text_encrypt.pack(side=ttk.RIGHT, anchor='ne', expand=ttk.YES, fill=ttk.BOTH)
        self.Text_encrypt.insert('1.0', 'RSA\n')
        self.Text_encrypt.insert('2.0', 'N:\n')
        self.Text_encrypt.insert('3.0', 'D:\n')

        self.Text_encrypt.insert('4.0', '\n' * 20)
        self.Text_encrypt.insert('20.0', 'AES\n')
        self.Text_encrypt.insert('21.0', 'PLAIN_TEXT:\n')
        self.Text_encrypt.insert('22.0', 'ENCRYPT_TEXT:\n')

    def get_input(self):
        # print(self.Text_input.get('0.0', ttk.END))
        return self.Text_input.get('0.0', ttk.END)

    # def send_message(self):
    #     btn_send = ttk.Button

    def send_msg(self, event):
        input_ = self.get_input()
        self.encrypt_input = self.aes.aes_encrypt(input_.encode('utf-8'))
        if input_[0] == '\n':
            tk.messagebox.showwarning(message='Empty Message')
            return 'break'
        strMsg = "我:" + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n'

        self.text_set(strMsg, input_, 'right', 'green')

        self.Text_input.delete("0.0", ttk.END)

        self.Text_encrypt.delete("0.0", ttk.END)
        self.Text_encrypt.insert('1.0', 'RSA\n')
        self.Text_encrypt.insert('2.0', 'N:{}\n'.format(self.rsa.n))
        self.Text_encrypt.insert('3.0', 'D:{}\n'.format(self.rsa.d))

        self.Text_encrypt.insert('4.0', '\n' * 20)
        self.Text_encrypt.insert('20.0', 'AES\n')
        self.Text_encrypt.insert('21.0', 'PLAIN_TEXT:{}\n'.format(input_))
        self.Text_encrypt.insert('22.0', 'ENCRYPT_TEXT:{}\n'.format(self.encrypt_input))

        self.client_socket.send(self.encrypt_input)

    def run(self):
        # TODO:整一个临时等待链接窗
        # self.wait_window = ttk.Window()
        # self.chat_window.title('Connecting....')
        # self.chat_window.geometry('100x80')
        # self.wait_text = ttk.Text(self.wait_window)
        # self.wait_text.insert("end","Connecting now,PLZ wait")
        # self.wait_text.tag_add('temp', '1.0', ttk.END)
        # self.wait_text.tag_configure('tmep', justify='center', foreground='blue')
        # self.wait_window.mainloop()

        self.client_socket, self.client_addr = self.server.accept()

        swap_th = threading.Thread(target=self.rsa_aes)
        swap_th.start()
        swap_th.join()

        threading.Thread(target=self.recv_from_client).start()

    def dh_swap(self):

        key_info = self.client_socket.recv(1024).decode('utf-8').strip().replace('\n', '').replace('\r', '').split(',')
        server_dh = Server_DH(int(key_info[0]), int(key_info[1]))

        self.client_socket.send(str(server_dh.self_public_key).encode('utf-8'))
        oppo_public_key = key_info[2]
        server_dh.calc_share_key(int(oppo_public_key))

        # print('key_info:', key_info)
        # print('server_public_key:', server_dh.self_public_key)
        self.share_key = str(server_dh.share_key).encode()
        self.aes = Server_AES(self.share_key[:16], self.share_key[-16:])

    def rsa_aes(self):
        self.rsa = Sever_RSA()
        n = self.rsa.n
        e = self.rsa.e
        rsa_info = '{},'.format(n) + '{}'.format(e)

        self.client_socket.send(rsa_info.encode('utf-8'))
        encrypt_rand_num = self.client_socket.recv(1024).decode('utf-8').strip().replace('\n', '').replace('\r', '')
        # print('encrypt', encrypt_rand_num)
        # print('n', n)
        # print('e', e)
        # print('d', self.rsa.d)
        # print('p', self.rsa.p)
        # print('q',self.rsa.q)
        rand_num = self.rsa.rsa_decrypt(int(encrypt_rand_num))

        aes_string = str(rand_num).encode('utf-8')
        aes_key = aes_string[:16]
        aes_iv = aes_string[-16:]
        # print(aes_string)
        self.aes = Server_AES(aes_key, aes_iv)

    def recv_from_client(self):
        """
        接收客户端信息
        """
        while True:
            recv_info = self.client_socket.recv(1024)
            recv_info = self.aes.aes_decrypt(recv_info).decode('utf-8').strip().replace('\n', '').replace('\r',
                                                                                                          '') + '\n'
            # print('server{} say: '.format((self.IP, self.PORT)), recv_info)
            strMsg = "对方:" + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n'

            self.text_set(strMsg, recv_info + '\n', 'left', 'pink')

    def text_set(self, strMsg, input_, site, color):
        self.start = self.end
        before = int(self.Text_history.index('end').split('.')[0]) - 1
        self.Text_history.insert("end", strMsg)
        self.Text_history.insert("end", input_)
        after = int(self.Text_history.index('end').split('.')[0]) - 1
        self.end = self.start + (after - before)
        tn = 'justify{}'.format(random.randint(0, 999999))
        self.Text_history.tag_add(tn, self.start, self.end)
        self.Text_history.tag_configure(tn, justify=site, foreground=color)

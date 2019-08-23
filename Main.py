# -*- coding: cp949 -*-
import os
import tkinter
from tkinter import filedialog
from tkinter import messagebox
import tkinter.ttk
import time
from datetime import datetime
from tkinter import *
from tkinter import ttk
import zipfile
import PyPDF2
import stat

window = tkinter.Tk()
window.title("Windows Server vulnerability check")
window.geometry("430x260+750+250")
window.resizable(False,False)

id = StringVar()
pw = StringVar()
ip = StringVar()
R_pw = StringVar()

value = []

global state_label0,state_label1,state_label2,state_label3,state_label4

global start_button,button

v = StringVar()
check = IntVar()

def FRAME():
    global start_button,button,c1
    global id,pw,ip,R_pw

    labelframe1=tkinter.LabelFrame(window,width=250,height=55,text="Administrator ID")
    labelframe1.place(x=10,y=5)

    ID=tkinter.Entry(window,width = 30,textvariable=id)
    ID.place(x=20,y=30)

    labelframe2=tkinter.LabelFrame(window,width=250,height=55,text="Administrator PW")
    labelframe2.place(x=10,y=65)

    PW=tkinter.Entry(window,width = 30,textvariable = pw,show = "*")
    PW.place(x=20,y=90)

    labelframe3=tkinter.LabelFrame(window,width=250,height=55,text="Connect Server IP")
    labelframe3.place(x=10,y=130)

    IP=tkinter.Entry(window,width = 30,textvariable=ip)
    IP.place(x=20,y=155)

    labelframe4=tkinter.LabelFrame(window,width=300,height=55,text="Report Save Dir Select")
    labelframe4.place(x=10,y=195)

    c1 = ttk.Checkbutton(window, text="보고서 PW 설정", variable = check , command = checkbox)
    c1.place(x=315,y=215)
    check.set(0)

    labelframe4=tkinter.LabelFrame(window,width=400,height=50,text="Report PW")
    labelframe4.place(x=10,y=260)

    Report_PW=tkinter.Entry(window,width = 53,textvariable = R_pw)
    Report_PW.place(x=20,y=280)

    #select DIR
    entry=tkinter.Entry(window,width = 30,state="readonly",textvariable=v)
    entry.place(x=20,y=220)

    button = tkinter.Button(window,width=5,command=select_DIR, repeatdelay=1000, repeatinterval=100,text="...")
    button.place(x=250,y=215)

    start_button = tkinter.Button(window,width=15,height=3,command=lambda:check_string(id,pw,ip,R_pw),text="Check Server")
    start_button.place(x=290,y = 75)

    window.mainloop()

def New_Frame():
    global window2
    global state_label0,state_label1,state_label2,state_label3,state_label4,state_label5

    #State window option
    window2 = tkinter.Tk()
    window2.title("STATUS")
    window2.geometry("800x120+600+650")
    window2.resizable(False,False)
    window2.overrideredirect(1)

    #UI
    label0 = tkinter.Label(window2,text="서버 연결",width=10)
    label0.place(x=50,y=30)
    state_label0 = tkinter.Label(window2,text="연결 전",width=10,state=DISABLED)
    state_label0.place(x=50,y=60)

    label1 = tkinter.Label(window2,text="계정 관리",width=10)
    label1.place(x=180,y=30)
    state_label1 = tkinter.Label(window2,text="점검 전",width=10,state=DISABLED)
    state_label1.place(x=180,y=60)

    label2 = tkinter.Label(window2,text="서비스 관리",width=10)
    label2.place(x=300,y=30)
    state_label2 = tkinter.Label(window2,text="점검 전",width=10,state=DISABLED)
    state_label2.place(x=300,y=60)

    label3 = tkinter.Label(window2,text="로그 관리",width=10)
    label3.place(x=420,y=30)
    state_label3 = tkinter.Label(window2,text="점검 전",width=10,state=DISABLED)
    state_label3.place(x=420,y=60)

    label4 = tkinter.Label(window2,text="보안 관리",width=10)
    label4.place(x=540,y=30)
    state_label4 = tkinter.Label(window2,text="점검 전",width=10,state=DISABLED)
    state_label4.place(x=540,y=60)

    label5 = tkinter.Label(window2,text="문서 작성",width=10)
    label5.place(x=660,y=30)
    state_label5 = tkinter.Label(window2,text="작성 전",width=10,state=DISABLED)
    state_label5.place(x=660,y=60)

    temp_label1 = tkinter.Label(window2,text="_________")
    temp_label1.place(x=125,y=25)
    temp_label2 = tkinter.Label(window2,text="_________")
    temp_label2.place(x=250,y=25)
    temp_label3 = tkinter.Label(window2,text="_________")
    temp_label3.place(x=375,y=25)
    temp_label4 = tkinter.Label(window2,text="_________")
    temp_label4.place(x=495,y=25)
    temp_label4 = tkinter.Label(window2,text="_________")
    temp_label4.place(x=615,y=25)

def check_string(id,pw,ip,R_pw):

    global window2
    global start_button, c1
    global v

    if id.get() == '' or pw.get() == '' or ip.get() == '' or v.get() == '':
        if check.get() == 0:
            tkinter.messagebox.showerror("오류","관리자 계정 정보 / IP 주소 / 보고서 저장 위치를 모두 입력하여 주세요.")
        else:
            tkinter.messagebox.showerror("오류","관리자 계정 정보 / IP 주소 / 보고서 저장 위치 / 보고서 패스워드를 모두 입력하여 주세요.")

    else:
        if check.get() != 0 and R_pw.get() == '':
            tkinter.messagebox.showerror("오류","보고서 패스워드를 입력하여 주세요.")

        else:
            Q = tkinter.messagebox.askyesno("확인","점검을 실행하시겠습니까?")

            if Q == 1:
                New_Frame()

                flag = Connect_server(id,pw,ip,R_pw)

                if flag == 0:
                    tkinter.messagebox.showerror("Connection ERROR","점검 서버와 연결하는 중 오류가 발생하였습니다. 계정과 서버의 정보를 다시 입력하여 주세요.")
                    id.set("")
                    pw.set("")
                    ip.set("")
                    v.set("")
                    R_pw.set("")
                    check.set(0)

                elif flag == 1:
                    tkinter.messagebox.showinfo("점검 완료!","취약점 점검이 완료되었습니다!\n" + v.get() + "폴더에 보고서 파일이 저장되었습니다.")
            
                window2.destroy()

            start_button.config(text="Check Server",state=ACTIVE)
            button.config(state=ACTIVE)
            check.set(0)
            c1.config(state=ACTIVE)

def select_DIR():
    global v
    dirname=filedialog.askdirectory()
    v.set(dirname)

def checkbox():
    global window ,check

    if check.get() == 0:
        window.geometry("430x260+750+250")
    else:
        window.geometry("430x320+750+250")   

def start_command(command):
    return os.system(command)

def zip(src_path, dest_file):
    with zipfile.ZipFile(dest_file, 'w') as zf:
        rootpath = src_path
        for (path, dir, files) in os.walk(src_path):
            for file in files:
                fullpath = os.path.join(path, file)
                relpath = os.path.relpath(fullpath, rootpath);
                zf.write(fullpath, relpath, zipfile.ZIP_DEFLATED)
        zf.close()

def encrypt_resultpdf(pdf_path,password):
    pdfFile = open(pdf_path + "\\Result_Report.pdf", 'rb')

    pdfReader = PyPDF2.PdfFileReader(pdfFile)
    pdfWriter = PyPDF2.PdfFileWriter()

    for pageNum in range(pdfReader.numPages):
        pdfWriter.addPage(pdfReader.getPage(pageNum))
    pdfWriter.encrypt(password)

    resultPdf = open(pdf_path + "\\Report.pdf", 'wb')
    pdfWriter.write(resultPdf)
    resultPdf.close()
    pdfFile.close()

def Connect_server(id,pw,ip,R_pw):
    
    global window2
    global start_button,button
    global state_label0,state_label1,state_label2,state_label3,state_label4,state_label5
    global v ,check
    global c1

    #Get Date
    date = datetime.today().strftime("%Y_%m_%d_%H_%M")

    #disable start button
    start_button.config(text="점검 중...",state=DISABLED)
    button.config(state=DISABLED)
    c1.config(state=DISABLED)

    # set command and check_1 label setting in State window
    state_label0.config(text="연결 중",state=ACTIVE,fg="red")

    window2.update()

    command = 'powershell.exe -window hidden -ExecutionPolicy Bypass -File ./connect/connect_test.ps1 ' + id.get() + ' ' + pw.get() + ' ' + ip.get()
    flag = start_command(command)

    if flag == 0:
        state_label0.config(text="연결 완료!",state=ACTIVE,fg='green')
    else:
        state_label0.config(text="연결 오류!",state=ACTIVE,fg='red')
        return 0

    # set command and check_1 label setting in State window
    state_label1.config(text="점검 중",state=ACTIVE,fg="red")

    window2.update()

    command = 'powershell.exe -window hidden -ExecutionPolicy Bypass -File ./execute/execute_1.ps1 ' + id.get() + ' ' + pw.get() + ' ' + ip.get()
    flag = start_command(command)

    if flag == 0:
        state_label1.config(text="점검 완료",state=ACTIVE,fg='green')
    else:
        state_label1.config(text="오류!",state=ACTIVE,fg='red')       
    
    window2.update()

    # set command and check_2 label setting in State window 
    state_label2.config(text="점검 중",state=ACTIVE,fg="red")

    window2.update()

    command = 'powershell.exe -window hidden -ExecutionPolicy Bypass -File ./execute/execute_2.ps1 ' + id.get() + ' ' + pw.get() + ' ' + ip.get()
    flag = start_command(command)

    if flag == 1:
        state_label2.config(text="오류!",state=ACTIVE,fg='red') 

    window2.update()

    # set command and check_3
    command = 'powershell.exe -window hidden -ExecutionPolicy Bypass -File ./execute/execute_3.ps1 ' + id.get() + ' ' + pw.get() + ' ' + ip.get()
    flag = start_command(command)
    
    if flag == 0:
        state_label2.config(text="점검 완료",state=ACTIVE,fg='green')
    else:
        state_label2.config(text="오류!",state=ACTIVE,fg='red')  

    window2.update()

    # set command and check_4 label setting in State window
    state_label3.config(text="점검 중",state=ACTIVE,fg="red")

    window2.update()

    command = 'powershell.exe -window hidden -ExecutionPolicy Bypass -File ./execute/execute_4.ps1 ' + id.get() + ' ' + pw.get() + ' ' + ip.get()
    flag = start_command(command)

    if flag == 0:
        state_label3.config(text="점검 완료",state=ACTIVE,fg='green')
    else:
        state_label3.config(text="오류!",state=ACTIVE,fg='red')  
    
    window2.update()

    # set command and check_5 label setting in State window
    state_label4.config(text="점검 중",state=ACTIVE,fg="red")

    window2.update()

    command = 'powershell.exe -window hidden -ExecutionPolicy Bypass -File ./execute/execute_5.ps1 ' + id.get() + ' ' + pw.get() + ' ' + ip.get()
    flag = start_command(command)

    if flag == 0:
        state_label4.config(text="점검 완료",state=ACTIVE,fg='green')
    else:
        state_label4.config(text="오류!",state=ACTIVE,fg='red')  

    window2.update()


    ##write document
    state_label5.config(text="작성 중",state=ACTIVE,fg="red")
    window2.update()

    #make dir name
    dir_name = v.get() + '/' + date
    dir_name = dir_name.replace("/","\\")
    
    if not os.path.exists(dir_name):
        os.mkdir(dir_name)

    #write command
    command = 'powershell.exe -window hidden -ExecutionPolicy Bypass -File ./getresult/Get_result.ps1 ' + id.get() + ' ' + pw.get() + ' ' + ip.get() + ' ' + dir_name + ' ' + date
    flag = start_command(command)

    if flag != 0:
        state_label5.config(text="오류!",state=ACTIVE,fg='red')
         
    zip(dir_name+"\\temp",dir_name+"\\Result_Report.docx.zip")

    #convert PDF
    command = 'powershell.exe -window hidden -ExecutionPolicy Bypass -File ./getresult/convertpdf.ps1 ' + dir_name
    flag = start_command(command)

    if check.get() == 0:
        os.rename(dir_name + "\\Result_Report.pdf",dir_name + "\\Report.pdf")
    else:
        encrypt_resultpdf(dir_name,R_pw.get())
        os.remove((dir_name + "\\Result_Report.pdf"))

    if flag == 0:
        state_label5.config(text="작성 완료",state=ACTIVE,fg="#FF0000")
    else:
        state_label5.config(text="오류!",state=ACTIVE,fg="red")  

    window2.update()

    return 1

FRAME()



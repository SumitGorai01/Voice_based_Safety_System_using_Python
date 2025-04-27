from tkinter import *
from tkinter import Frame, Label, Button ,messagebox
from PIL import Image, ImageTk
import mysql.connector
from datetime import datetime , timedelta
import cv2
import os
import requests
import speech_recognition as sr
import geocoder
import json
import threading

# EmailJS credentials
EMAILJS_SERVICE_ID = "service_fytsm3j"
EMAILJS_TEMPLATE_ID = "template_wbldyiv"
EMAILJS_PUBLIC_KEY = "7ciaaJc-pKcWsBg23"

tk = Tk()
tk.geometry("1200x750+150+10")
tk.title("Trinetra")
tk.configure(bg="white")

#global variable
photo_filename = None

# db conn
def connect_db():
    return mysql.connector.connect(host="localhost", user="root", password="root", database="mca_2025")

# send email funnction
def send_email_with_emailjs(from_name, user_email, emer_email, location):
    url = "https://api.emailjs.com/api/v1.0/email/send"
    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "service_id": EMAILJS_SERVICE_ID,
        "template_id": EMAILJS_TEMPLATE_ID,
        "user_id": EMAILJS_PUBLIC_KEY,
        "template_params": {
            "from_name": from_name,
            "to_name": user_email,
            "to_email": emer_email,
            "message": location
        }
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        print("Email sent successfully via EmailJS.")
        print(f"name={from_name} , user_email={user_email} , emer_emal={emer_email}")
    else:
        print(f"Failed to send email: {response.status_code} - {response.text}")
        print(f"name={from_name} , user_email={user_email} , emer_emal={emer_email}")
'''
# send whatsapp message
def send_whatsapp_message(from_name,emer_mobile , location):
    delay_seconds=5
    print(f"⏳ Waiting for {delay_seconds} seconds before sending the message...")
    
    time.sleep(delay_seconds)  # Add a delay before sending the message

    # Get the current time
    now = datetime.now()
    send_time = now + timedelta(seconds=delay_seconds)  # Add delay seconds to current time
    hour = send_time.hour
    minute = send_time.minute

    # Emergency alert message
    message = f"""
    Hello Dear,

    This is an urgent emergency notification regarding your friend, {from_name}.

    They have triggered an emergency alert and may be in distress.

    📍 Last known location: {location}

    ⚠️ Please try to reach out to them or provide assistance if possible.

    Every second counts. Your response could make a difference.

    Stay safe,  
    Emergency Alert System
    """
    emer_mobile = "+91"+emer_mobile

    # Send the message at the calculated time
    kit.sendwhatmsg(emer_mobile, message, hour, minute)
    print(f"✅ WhatsApp message will be sent at {hour}:{minute}")

'''
    
# voice listener function
def voice_listener(from_name, user_email, emer_mobile , emer_email):
    global listening
    listening = True
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        print("🎤 Listening for 'help' or 'logout'...")
        while listening:
            try:
                audio = recognizer.listen(source, timeout=5)
                text = recognizer.recognize_google(audio).lower()
                print(f"🎧 Recognized: {text}")
                if "help" in text:
                    location = geocoder.ip('me').address
                    print(f"📍 Detected Location: {location}")
                    #send_whatsapp_message(from_name,emer_mobile , location) 
                    send_email_with_emailjs(from_name, user_email, emer_email, location)
                elif "logout" in text:
                    print("🚪 Logging out...")
                    logout()
                    break
            except sr.WaitTimeoutError:
                continue
            except Exception as e:
                print(f"!!Voice recognition error: {e}")


# Function to log out
def logout():
    global dashboard,listening
    listening = False
    dashboard.destroy()
    messagebox.showinfo("Logout", "You have been logged out successfully")    
    print("User logged out successfully.")  

# Function to fetch user details
def fetch_user_details(email):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM safety_users WHERE email=%s", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def view_profile_window(email):
    user = fetch_user_details(email)
    if not user:
        messagebox.showerror("Error", "User not found")
        return

    profile_win = Toplevel()
    profile_win.title("View Profile")
    profile_win.geometry("500x650+500+50")
    photo_path = user[7]
    Label(profile_win, text="User Profile", font=("Arial", 18, "bold")).pack(pady=10)
        
    Label(profile_win, text=f"Name: {user[1]}", font=("Arial", 14)).pack(pady=5)
    Label(profile_win, text=f"Email: {user[2]}", font=("Arial", 14)).pack(pady=5)
    Label(profile_win, text=f"Mobile: {user[3]}", font=("Arial", 14)).pack(pady=5)    
    Label(profile_win, text=f"Emergency Mobile: {user[5]}", font=("Arial", 14)).pack(pady=5)
    Label(profile_win, text=f"Emergency Email: {user[6]}", font=("Arial", 14)).pack(pady=5)
    Label(profile_win, text=f"Photo: {photo_path}", font=("Arial", 14)).pack(pady=5)
    
    img = Image.open("./"+photo_path)  
    img = img.resize((400, 250), Image.LANCZOS)
    img = ImageTk.PhotoImage(img)
    img_label = Label(profile_win, image=img)
    img_label.image = img  
    img_label.pack(pady=10)
    Button(profile_win, text="Close", font=("Arial", 12), command=profile_win.destroy).pack(pady=20)
    
def update_profile(email):
    new_name = entry_new_name.get()
    new_mobile = entry_new_mobile.get()
    new_emergency_mobile = entry_new_em_mobile.get()
    new_emergency_email = entry_new_em_email.get()
    #new_photo_path = entry_photo_path.get()

    if not (new_name and new_mobile and new_emergency_mobile and new_emergency_email):
        messagebox.showwarning("Input Error", "Please fill in all fields")
        return

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE safety_users 
        SET name=%s, mobile=%s, emer_mobile=%s, emer_email=%s
        WHERE email=%s
    """, (new_name, new_mobile, new_emergency_mobile, new_emergency_email, email))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Profile updated successfully")
    update_win.destroy()

def update_profile_window(email):
    global update_win, entry_new_name, entry_new_mobile, entry_new_em_mobile, entry_new_em_email

    user = fetch_user_details(email)
    if not user:
        messagebox.showerror("Error", "User not found")
        return

    update_win = Toplevel()
    update_win.title("Update Profile")
    update_win.geometry("600x650+500+50")
    update_win.resizable(False, False)

    # Using grid() instead of pack() for layout
    Label(update_win, text="Update Profile", font=("Arial", 20, "bold")).grid(row=0, column=0, columnspan=2, pady=20)

    Label(update_win, text="Name:", font=("Arial", 14)).grid(row=1, column=0, padx=10, pady=5, sticky=E)
    entry_new_name = Entry(update_win, font=("Arial", 14), width=30)
    entry_new_name.insert(0, str(user[1] or ""))
    entry_new_name.grid(row=1, column=1, padx=10, pady=5)

    Label(update_win, text="Mobile No.:", font=("Arial", 14)).grid(row=2, column=0, padx=10, pady=5, sticky=E)
    entry_new_mobile = Entry(update_win, font=("Arial", 14), width=30)
    entry_new_mobile.insert(0, str(user[3] or ""))
    entry_new_mobile.grid(row=2, column=1, padx=10, pady=5)

    Label(update_win, text="Emergency Mobile:", font=("Arial", 14)).grid(row=3, column=0, padx=10, pady=5, sticky=E)
    entry_new_em_mobile = Entry(update_win, font=("Arial", 14), width=30)
    entry_new_em_mobile.insert(0, str(user[5] or ""))
    entry_new_em_mobile.grid(row=3, column=1, padx=10, pady=5)

    Label(update_win, text="Emergency Email:", font=("Arial", 14)).grid(row=4, column=0, padx=10, pady=5, sticky=E)
    entry_new_em_email = Entry(update_win, font=("Arial", 14), width=30)
    entry_new_em_email.insert(0, str(user[6] or ""))
    entry_new_em_email.grid(row=4, column=1, padx=10, pady=5)

    Label(update_win, text="Photo Path:", font=("Arial", 14)).grid(row=5, column=0, padx=10, pady=5, sticky=E)
    img = Image.open("./"+user[7])  
    img = img.resize((400, 250), Image.LANCZOS)
    img = ImageTk.PhotoImage(img)
    img_label = Label(update_win, image=img)
    img_label.image = img  
    img_label.grid(row=5,column=1)

    # Button frame using grid
    Button(update_win, text="Update", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", 
           padx=10, pady=5, command=lambda: update_profile(email)).grid(row=6, column=0, padx=10, pady=20)
    
    Button(update_win, text="Cancel", font=("Arial", 12, "bold"), bg="#f44336", fg="white", 
           padx=10, pady=5, command=update_win.destroy).grid(row=6, column=1, padx=10, pady=20)


# Function to reset password
def reset_password(email):
    new_password = entry_password.get()
    
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE safety_users SET password=%s WHERE email=%s", (new_password, email))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Password reset successfully")
    pass_window.destroy()

# user reset pass window
def reset_pass_window(email):
    global pass_window, entry_password,logged_email
    logged_email= email
    
    pass_window = Toplevel()
    pass_window.geometry("500x400+500+100")
    pass_window.title("Change Password")
    pass_window.resizable(False, False)
    Label(pass_window, text="New Password:", font=("Arial", 14)).pack()
    entry_password = Entry(pass_window, font=("Arial", 14), show="*")
    entry_password.pack()
    
    Button(pass_window, text="Reset Password", font=("Arial", 12), command=lambda:reset_password(logged_email)).pack(pady=5)

# User Dashboard Window
def open_user_dashboard_window(email):
    global entry_name, entry_mobile, entry_password, logged_in_email , dashboard
    logged_in_email = email
    
    dashboard = Toplevel()
    dashboard.geometry("1200x700+150+50")
    dashboard.title("SMS | User Dashboard")
    
    # Fetch user details
    user = fetch_user_details(logged_in_email)

    header = Frame(dashboard, bg="blue", height=100)
    header.pack(fill=X)
    Label(header, text="Welcome to Safety Management System", fg="white", bg="blue", font=("Arial", 25, "bold")).pack()

    
    # Navbar Container
    navbar_container = Frame(dashboard, bg="gray", height=50)
    navbar_container.pack(fill=X, pady=5, padx=10)
        
    # Logo on the Left Side
    logo = Label(navbar_container, text="SMS", fg="white", bg="gray", font=("Arial", 20, "bold"))
    logo.pack(side=LEFT, padx=10, pady=5)
        
    # Navbar on the Right Side
    navbar = Frame(navbar_container, bg="gray")
    navbar.pack(side=RIGHT)

    Button(navbar, text=f"Welcome : {email}", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5, command=lambda: print("Home Clicked")).pack(side=LEFT, padx=5, pady=5, ipady=5)
    Button(navbar, text="View Profile", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5, command=lambda: view_profile_window(email)).pack(side=LEFT, padx=5, pady=5, ipady=5)
    Button(navbar, text="Edit Profile",font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5, command=lambda: update_profile_window(email)).pack(side=LEFT, padx=5, pady=5, ipady=5)
    Button(navbar, text="Change Password", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white",padx=10, pady=5, command=lambda:reset_pass_window(email)).pack(side=LEFT, padx=5, pady=5, ipady=5)
    Button(navbar, text="Logout", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5, command=logout).pack(side=LEFT, padx=5, pady=5, ipady=5)

    # Body Content
    body = Frame(dashboard, bg="white")
    body.pack(fill=BOTH, expand=True, padx=10, pady=5)
    Label(body, text="Welcome to User Dasboard.", font=("Arial", 18)).pack()

    img = Image.open("./bg1.jpg")  
    img = img.resize((1000, 400), Image.LANCZOS)
    img = ImageTk.PhotoImage(img)
    img_label = Label(body, image=img)
    img_label.image = img  
    img_label.pack(pady=10)

    footer = Frame(dashboard, bg="black", height=100)
    footer.pack(fill=X, side=BOTTOM)
    Label(footer, text="© 2025 | All Right Reserved | sms.com ", fg="white", bg="black", font=("Arial", 20)).pack()
      
def login_user():
    email = entry_login_email.get()
    password = entry_login_password.get()
    
    if email == "" or password == "":
        messagebox.showerror("Error", "All fields are required")
        return
    
    try:
        conn = connect_db()
        cursor = conn.cursor()

        # Corrected query execution
        query = "SELECT * FROM safety_users WHERE email = %s AND password = %s"
        cursor.execute(query, (email, password))
        user = cursor.fetchone()  # Fetch a single user record

        if user:
            messagebox.showinfo("Success", "Login Successful")
            login_window.destroy()
            open_user_dashboard_window(email)
            # Start voice listener in background
            threading.Thread(target=voice_listener, args=(user[1],user[2],user[3], user[6]), daemon=True).start()

        else:
            messagebox.showerror("Error", "Invalid email or password")

    except mysql.connector.Error as err:
        messagebox.showerror("Database Error", f"Error: {err}")

#register
def register_user():
    global photo_filename
    name = entry_reg_name.get()
    email = entry_reg_email.get()
    mobile = entry_reg_mobile.get()
    password = entry_reg_password.get()
    emer_mobile = entry_reg_em_mobile.get()
    emer_email = entry_reg_em_email.get()
    
    print("photo :",photo_filename)
    
    if name == "" or password == "" or email =="" or mobile == "":
        messagebox.showerror("Error", "All fields are required")
        return
    
    try:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO safety_users (name, email, mobile,password,emer_mobile,emer_email,photo) VALUES (%s,%s,%s, %s, %s, %s,%s)", 
                       (name, email, mobile, password,emer_mobile,emer_email,photo_filename))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Registration Successful")
        register_window.destroy()
        open_login_window()
    except mysql.connector.Error as err:
        messagebox.showerror("Database Error", f"Error: {err}")

def show_about():
    about_window = Toplevel()
    about_window.title("About Us")
    about_window.geometry("500x400+500+100")
    about_window.configure(bg="#f5f5f5")

    # Logo
    try:
        logo_img = Image.open("./about.png").resize((80, 80))
        logo_photo = ImageTk.PhotoImage(logo_img)
        Label(about_window, image=logo_photo, bg="#f5f5f5").pack(pady=10)
        # Keep a reference to prevent garbage collection
        about_window.logo_ref = logo_photo
    except:
        Label(about_window, text="VoiceAlert App", font=("Helvetica", 18, "bold"), bg="#f5f5f5", fg="#2c3e50").pack(pady=10)

    Label(about_window, text="About Voice Emergency System", font=("Arial", 16, "bold"), bg="#f5f5f5", fg="#34495e").pack(pady=5)

    about_text = """This app is built to assist users in emergency situations using voice commands.

When the user says 'hello' after logging in, an alert email is sent with their current location to the registered emergency contact.

Built with:
- Python & Tkinter
- SpeechRecognition
- SMTP for email
- Geocoder API
"""
    Label(about_window, text=about_text, wraplength=400, justify=LEFT, font=("Arial", 12), bg="#f5f5f5", fg="#555").pack(padx=20, pady=10)


def show_contact():
    contact_window = Toplevel()
    contact_window.title("Contact Us")
    contact_window.geometry("500x400+500+100")
    contact_window.configure(bg="#f5f5f5")

    try:
        logo_img = Image.open("./contact.png").resize((80, 80))
        logo_photo = ImageTk.PhotoImage(logo_img)
        Label(contact_window, image=logo_photo, bg="#f5f5f5").pack(pady=10)
        contact_window.logo_ref = logo_photo
    except:
        Label(contact_window, text="VoiceAlert App", font=("Helvetica", 18, "bold"), bg="#f5f5f5", fg="#2c3e50").pack(pady=10)

    Label(contact_window, text="Get in Touch", font=("Arial", 16, "bold"), bg="#f5f5f5", fg="#34495e").pack(pady=5)

    contact_text = """Developer: Sumit Gorai
Email: support@voicealertapp.com
Phone: +91-9876543210

For feedback, issues, or collaboration, feel free to reach out!
"""
    Label(contact_window, text=contact_text, wraplength=400, justify=LEFT, font=("Arial", 12), bg="#f5f5f5", fg="#555").pack(padx=20, pady=10)

def capture_photo():
    global photo_filename
    cap = cv2.VideoCapture(0)
    cv2.namedWindow("Capture Photo || Press SPACE to capture or ESC to exit")

    photo_filename = None

    while True:
        rval, frame = cap.read()
        cv2.imshow("Capture Photo || Press SPACE to capture or ESC to exit", frame)

        key = cv2.waitKey(20)
        if key == 27:  # ESC to cancel
            print("Closing without saving.")
            break
        elif key == 32:  # SPACE to capture
            photo_filename = f"profile_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            cv2.imwrite(photo_filename, frame)
            print(f"Photo saved as {photo_filename}")
            break

    cap.release()
    cv2.destroyAllWindows()

    return photo_filename

def handle_capture_and_preview():
    global captured_image_label

    photo_path = capture_photo()
    if photo_path:
        img = Image.open(photo_path)
        img = img.resize((250, 150))
        photo = ImageTk.PhotoImage(img)

        captured_image_label.configure(image=photo)
        captured_image_label.image = photo  # Keep reference!


def open_register_window():
    global register_window, entry_reg_name, entry_reg_email,entry_reg_mobile,entry_reg_password ,captured_image_label,entry_reg_em_mobile,entry_reg_em_email
    
    register_window = Toplevel()
    register_window.geometry("600x700+500+30")
    register_window.title("Register YourSelf")
    register_window.resizable(False, False)
    img1 = Image.open("./signup.png")
    img1 = img1.resize((50, 50))
    img1 = ImageTk.PhotoImage(img1)
    img_label = Label(register_window, image=img1)
    img_label.image = img1  
    img_label.place(x=250,y=0)
    Label(register_window, text="Signup", font=("Arial", 20, "bold")).grid(row=0, column=0, columnspan=2, pady=(70,10))
    
    Label(register_window, text="Name:", font=("Arial", 18)).grid(row=1, column=0, padx=10, pady=5, sticky=E)
    entry_reg_name = Entry(register_window, font=("Arial", 18), width=25)
    entry_reg_name.grid(row=1, column=1, padx=10, pady=5)
    
    Label(register_window, text="Email:", font=("Arial", 18)).grid(row=2, column=0, padx=10, pady=5, sticky=E)
    entry_reg_email = Entry(register_window, font=("Arial", 18), width=25)
    entry_reg_email.grid(row=2, column=1, padx=10, pady=5)
    
    Label(register_window, text="Mobile:", font=("Arial", 18)).grid(row=3, column=0, padx=10, pady=5, sticky=E)
    entry_reg_mobile = Entry(register_window, font=("Arial", 18), width=25)
    entry_reg_mobile.grid(row=3, column=1, padx=10, pady=5)
    
    Label(register_window, text="Emergency Mobile:", font=("Arial", 18)).grid(row=4, column=0, padx=10, pady=5, sticky=E)
    entry_reg_em_mobile = Entry(register_window, font=("Arial", 18), width=25)
    entry_reg_em_mobile.grid(row=4, column=1, padx=10, pady=5)

    
    Label(register_window, text="Emergency Email:", font=("Arial", 18)).grid(row=5, column=0, padx=10, pady=5, sticky=E)
    entry_reg_em_email = Entry(register_window, font=("Arial", 18), width=25)
    entry_reg_em_email.grid(row=5, column=1, padx=10, pady=5)
    
    Label(register_window, text="Password:", font=("Arial", 18)).grid(row=6, column=0, padx=10, pady=5, sticky=E)
    entry_reg_password = Entry(register_window, font=("Arial", 18), width=25, show="*")
    entry_reg_password.grid(row=6, column=1, padx=10, pady=5)


    img = Image.open("./camera.png")
    img = img.resize((40, 25))
    img = ImageTk.PhotoImage(img)
    img_label = Label(register_window, image=img)
    img_label.image = img  
   
    Label(register_window, text="Capture Photo:", font=("Arial", 18)).grid(row=7, column=0, padx=10, pady=5, sticky=E)
    # 📷 Capture Photo Button
    Button(register_window, text="Capture Photo", font=("Arial", 12, "bold"), bg="#2196F3", fg="white",
           padx=20, pady=5, command=handle_capture_and_preview,image=img).grid(row=7, column=1,padx=5, pady=5, sticky=W)
    # 📸 Frame for preview image
    preview_frame = Frame(register_window)
    preview_frame.grid(row=7, column=1, padx=5, pady=5, sticky=E)

    # 🖼️ Label (no width/height set)
    captured_image_label = Label(preview_frame)
    captured_image_label.pack(padx=5, pady=5)
        
    Button(register_window, text="Sign Up", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", 
           padx=10, pady=5, command=register_user).grid(row=8, column=1,padx=20, pady=5,sticky=S)
    
    Button(register_window, text="Reset", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", 
           padx=10, pady=5, command=reset).grid(row=8, column=1,sticky=E )
    
    Label(register_window, text="Already have an account? :", font=("Arial", 10)).grid(row=9, column=1, pady=15, sticky=S)
    link1 = Label(register_window, text="Sign In", font=("Arial", 14),fg="blue",cursor="hand2")
    link1.grid(row=9, column=1, sticky=E)
    link1.bind("<Button-1>", lambda e: open_login_window())

def open_login_window():
    global login_window, entry_login_email,entry_login_password
    
    login_window = Toplevel()
    login_window.geometry("500x400+500+100")
    login_window.title("Login")
    login_window.resizable(False, False)
    img = Image.open("./login.png") 
    img = img.resize((50, 50))
    img = ImageTk.PhotoImage(img)
    img_label = Label(login_window, image=img)
    img_label.image = img  
    img_label.place(x=220,y=20)
    
    Label(login_window, text="Login", font=("Arial", 20, "bold")).grid(row=0, column=0, columnspan=2, pady=(100,10))
        
    Label(login_window, text="Email:", font=("Arial", 18)).grid(row=1, column=0, padx=10, pady=5, sticky=E)
    entry_login_email = Entry(login_window, font=("Arial", 18), width=25)
    entry_login_email.grid(row=1, column=1, padx=10, pady=5)
        
    Label(login_window, text="Password:", font=("Arial", 18)).grid(row=2, column=0, padx=10, pady=5, sticky=E)
    entry_login_password = Entry(login_window, font=("Arial", 18), width=25, show="*")
    entry_login_password.grid(row=2, column=1, padx=10, pady=5)
    
    Button(login_window, text="Sign In", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", 
           padx=10, pady=5, command=login_user).grid(row=3, column=1,padx=20, pady=5,sticky=S)
    
    Button(login_window, text="Reset", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", 
           padx=10, pady=5, command=reset).grid(row=3, column=1,sticky=E )
    
    Label(login_window, text="Don't have an account? :", font=("Arial", 10)).grid(row=4, column=1, pady=15, sticky=S)
    link1 = Label(login_window, text="Sign Up", font=("Arial", 14),fg="blue",cursor="hand2")
    link1.grid(row=4, column=1, sticky=E)
    link1.bind("<Button-1>", lambda e: open_register_window())
    
def reset():
    entry_reg_name.delete(0, END)
    entry_reg_email.delete(0, END)
    entry_reg_mobile.delete(0, END)
    entry_reg_password.delete(0, END)
    entry_login_email.delete(0, END)
    entry_login_password.delete(0, END)  
    preview_frame.delete(0, END)
# Header
def header():
    header = Frame(tk, bg="blue", height=100)
    header.pack(fill=X)
    Label(header, text="Welcome to Safety Management System", fg="white", bg="blue", font=("Arial", 25, "bold")).pack()

# Footer
def footer():
    footer = Frame(tk, bg="black", height=100)
    footer.pack(fill=X, side=BOTTOM)
    Label(footer, text="© 2025 | All Right Reserved | TrinetraAlert.com ", fg="white", bg="black", font=("Arial", 20)).pack()


# home page start here

header()

# Navbar Container
navbar_container = Frame(tk, bg="gray", height=50)
navbar_container.pack(fill=X, pady=5, padx=10)
    
# Logo on the Left Side
logo = Label(navbar_container, text="Trinetra", fg="white", bg="gray", font=("Arial", 20, "bold"))
logo.pack(side=LEFT, padx=10, pady=5)
    
# Navbar on the Right Side
navbar = Frame(navbar_container, bg="gray")
navbar.pack(side=RIGHT)

Button(navbar, text="Home", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5, command=lambda: print("Home Clicked")).pack(side=LEFT, padx=5, pady=5, ipady=5)
Button(navbar, text="About", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5, command=show_about).pack(side=LEFT, padx=5, pady=5, ipady=5)
Button(navbar, text="Contact",font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5, command=show_contact).pack(side=LEFT, padx=5, pady=5, ipady=5)
Button(navbar, text="Login", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white",padx=10, pady=5, command=open_login_window).pack(side=LEFT, padx=5, pady=5, ipady=5)
Button(navbar, text="Signup", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5, command=open_register_window).pack(side=LEFT, padx=5, pady=5, ipady=5)
    
# Body Content
body = Frame(tk, bg="white")
body.pack(fill=BOTH, expand=True, padx=10, pady=15)

Label(
    body,
    text="Welcome to TrinetraAlert — 'The Eye That Never Sleeps'\nVoice Command-Based Safety Management System.",
    font=("Arial", 18),
    bg="white"
).pack()

# image slider
x=1
slider_running = True
slider = None
slider_label = Label(body)
slider_label.place(x=150, y=70)
def change_pic():
    global x , slider_label , slider
    if x==5:
        x=1
    img=Image.open("./bg"+str(x)+".jpg")
    img=img.resize((850,430))
    img=ImageTk.PhotoImage(img)
    slider_label.config(image=img)
    slider_label.image = img
    x=x+1
    slider = tk.after(3000,change_pic)

change_pic()

# Start button
def start_slider():
    global slider_running
    if not slider_running:
        slider_running = True
        change_pic()

# Stop button
def stop_slider():
    global slider_running, slider
    slider_running = False
    if slider:
        tk.after_cancel(slider)
        slider = None
# Start & Stop buttons
start_btn = Button(body, text="START", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", command=start_slider)
start_btn.place(x=450, y=520)

stop_btn = Button(body, text="STOP", font=("Arial", 12, "bold"), bg="#F44336", fg="white", command=stop_slider)
stop_btn.place(x=580, y=520)

footer()


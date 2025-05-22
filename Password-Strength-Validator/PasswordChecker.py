import tkinter as tk
import string

# password = input("Type in a password: ")

def loadCommonPasswordPhrases(file):
    with open(file, "r", encoding="utf-8") as f:
        return [
            line.strip().lower()
            for line in f
            if len(line.strip()) >= 3
        ]
    

common_pass_phrases = loadCommonPasswordPhrases("Pwdb_top-10000.txt")
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 64
MAX_PENALTY = 20


def checkPasswordStrength(password):
    if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH: return "Password needs to be at least between 8-64 characters long!"

    score = 0

    #Gives score for each type of unique character used
    for char in set(password):
        if char in string.ascii_lowercase: score+=1
        if char in string.ascii_uppercase: score+=2
        if char in string.digits: score+=2
        if char in string.punctuation: score+=3

    #Add score for the length of the password
    score += len(password) // 8

    #Add bonus score for diversity of characters
    diversity = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password)
    ])

    score += diversity*2

    #Checks common phrases used in passwords
    lowered = password.lower()
    penalty = 0
    for phrase in common_pass_phrases:
        count = lowered.count(phrase)
        if count > 0:
            penalty += 3
            if penalty >= MAX_PENALTY:
                penalty = MAX_PENALTY
                break
    #Apply penalty for used common phrases
    score -= penalty

    if score < 0: score = 0

    if score < 8: return "Very Weak"
    elif score < 18: return "Weak"
    elif score < 25: return "Moderate"
    elif score < 30: return "Strong"
    else: return "Very Strong"


# print(checkPasswordStrength(password))

def handleOnClick():
    result = checkPasswordStrength(entry.get())
    text_colour = "darkgrey"
    match result:
        case ("Very Weak" | "Weak"):
            text_colour="red"
        case "Moderate":
            text_colour="yellow"
        case "Strong":
            text_colour="green"
        case "Very Strong":
            text_colour="darkgreen"       

    result_label.config(text=result, fg=text_colour)

win = tk.Tk()
win.geometry("640x320")
win.title("Password Strength Validator")
win.configure(bg="lightblue")

label = tk.Label(win, text="Password Strength Checker", font=("Ubuntu", 32), fg="white")
label.pack(padx=20, pady=20)
label.configure(bg="lightblue")

entry = tk.Entry(win, width=35, font=("Ubuntu", 20),justify="center")
entry.pack(padx=20, pady=10)

result_label = tk.Label(win, text="", font=("Arial", 18))
result_label.pack(pady=20)
result_label.configure(bg="lightblue")

button_border= tk.LabelFrame(win, bd=3, bg="black")
button_border.pack()

button = tk.Button(button_border, text="Check Strength", font=("Ubuntu", 12), command=handleOnClick)
button.pack()
win.mainloop()
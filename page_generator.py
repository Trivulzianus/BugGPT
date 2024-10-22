import openai
import sqlite3
import os
import re
from random import randrange

# Vulnerability dictionary
vulns = {0: 'sqli', 1: 'reflected xss', 2: 'easy ssrf', 3: 'easy idor', 4: 'easy xxe',
         5: 'time based sqli', 6: 'stored xss', 7: 'medium ssrf', 8: 'medium idor', 9: 'medium xxe',
         10: 'blind sqli', 11: 'DOM xss', 12: 'hard ssrf', 13: 'difficult idor', 14: 'difficult xxe',
         15: 'difficult sqli', 16: 'difficult xss', 17: 'extremely hard ssrf', 18: 'extremely difficult idor', 19: 'xxe',
         20: 'extremely difficult sqli', 21: 'highly sanitized xss', 22: 'ssrf', 23: 'idor', 24: 'xxe'}

# Choose a random vulnerability
random_vuln = randrange(25)
vuln = vulns[random_vuln]
print(f"Chosen Vulnerability: {vuln}")

openai.api_key = os.getenv("OPENAI_API_KEY")

# Request to generate the vulnerable web app
openai_response = openai.chat.completions.create(
    model="gpt-4o",
    messages=[
        {
            "role": "system",
            "content": "You are a cybersecurity engineer genius by day and artist by night. You have partnered"
                       "up with me on a project to create vulnerable web pages for security practitioners to "
                       "work against and test their knowledge. You create intricate puzzles which test the human brain."
                       "Your output is a python script which contains"
                       "all the necessary imports and function to initiate a flask app"
        },
        {
            "role": "user",
            "content": f"Create an engaging, difficult, and highly complex single web page for people to test their skills."
                       f"The app will feature the vulnerability {vuln}. Make the web page attractive, colorful, "
                       f"with a narrative. Make it complex and extremely difficult. Do not add hints in the HTML."
        }
    ],
    temperature=1,
    max_tokens=6000,
    top_p=1,
    frequency_penalty=0,
    presence_penalty=0
)

# Parse the generated vulnerable content
openai_content = openai_response.choices[0].message.content
openai_parsed_content = openai_content[10:-4]

# Request to generate the explanation and mitigation for the vulnerability
openai_fix = openai.chat.completions.create(
    model="gpt-4o",
    messages=[
        {
            "role": "system",
            "content": "You are a cybersecurity engineer genius by day who receives vulnerable static web apps written in python"
                       "and returns the solution for exploiting the vulnerable static web apps, as well as the explanation"
                       "for how to mitigate this vulnerability from the developer side. Your output is a well-structured markdown."
        },
        {
            "role": "user",
            "content": f"The following is a vulnerable web app written in python. Please explain the exploitation, and "
                       f"suggest best practices for developers to avoid this mistake in the future: {openai_parsed_content}"
        }
    ],
    temperature=1,
    max_tokens=6000,
    top_p=1,
    frequency_penalty=0,
    presence_penalty=0
)

# Parse the solution and mitigation content
openai_fix_content = openai_fix.choices[0].message.content

# Print the solution and mitigation
print(openai_fix_content)

# Function to run the Flask app
def run_flask_app():
    exec(openai_parsed_content, globals())

# Create a folder for each room and save the files
def create_room_folder(room_number):
    folder_name = f"Room_{room_number}"
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    # Save the vulnerable web app script
    vuln_file_path = os.path.join(folder_name, "vulnerable_app.py")
    with open(vuln_file_path, 'w', encoding='utf-8') as f:
        f.write(openai_parsed_content)

    # Save the explanation and mitigation in a markdown file
    explanation_file_path = os.path.join(folder_name, "explanation_and_mitigation.md")
    with open(explanation_file_path, 'w', encoding='utf-8') as f:
        f.write(openai_fix_content)

    print(f"Room {room_number} created with vulnerability: {vuln}")

# Determine the next room number by checking existing folders
def get_next_room_number():
    room_folders = [f for f in os.listdir() if os.path.isdir(f) and f.startswith("Room_")]
    if not room_folders:
        return 1
    else:
        room_numbers = [int(re.search(r"Room_(\d+)", folder).group(1)) for folder in room_folders]
        return max(room_numbers) + 1

# Get the next room number and create the folder
next_room_number = get_next_room_number()
create_room_folder(next_room_number)

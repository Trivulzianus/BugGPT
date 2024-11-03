from openai import OpenAI
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

client = OpenAI(api_key=openai.api_key)
# Request to generate the vulnerable web app
openai_response = client.chat.completions.create(
    model="o1-preview",
    messages=[
        {
            "role": "user",
            "content": f"Create an engaging, difficult, and highly complex single web page for security professionals to have a safe environment"
                       f" to test their skills. Create a page masquerading as a common target for attackers, like a bank,"
                       f"marketplace, airport, , government office, etc."
                       f"The app will feature the vulnerability {vuln}. Make the web page attractive, professional, "
                       f"with a convincing cover story. include all the necessary python imports, as I will run python exec() on your"
                       f"output"
        }
    ]
)

print(openai_response.choices[0].message.content)

# Parse the generated vulnerable content
openai_content = openai_response.choices[0].message.content
openai_parsed_content = openai_content[openai_content.find('from flask'):openai_content.find('if __name__ == ')+50]

# Request to generate the explanation and mitigation for the vulnerability
openai_fix = client.chat.completions.create(
    model="o1-mini",
    messages=[
        {
            "role": "user",
            "content": f"The following is a vulnerable web app written in python. Please explain the exploitation, and "
                       f"suggest best practices for developers to avoid this mistake in the future: {openai_parsed_content}"
        }
    ]
)

# Parse the solution and mitigation content
openai_fix_content = openai_fix.choices[0].message.content

# Print the solution and mitigation
print(openai_fix_content)

# Use Regex to extract room name
title_match = re.search(r'<title>(.*?)<\/title>', openai_parsed_content, re.IGNORECASE)
room_name = ''
if title_match:
    room_name = title_match.group(1).replace(':', ' ') if (':' in title_match.group(1)) else title_match.group(1)

# Create a folder for each room and save the files
def create_room_folder(room_number):
    folder_name = f"Room_{room_number}_{room_name}"
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    # Save the vulnerable web app script
    vuln_file_path = os.path.join(folder_name, "vulnerable_app.py")
    with open(vuln_file_path, 'w', encoding='utf-8') as f:
        f.write(openai_parsed_content[:-1] + ')')

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

import openai
import sqlite3
import os
import re
from random import randrange

openai.api_key = os.getenv("OPENAI_API_KEY")

vulns = {0: 'sqli', 1: 'reflected xss', 2: 'easy ssrf', 3: 'easy idor', 4: 'easy xxe',
         5: 'time based sqli', 6: 'stored xss', 7: 'medium ssrf', 8: 'medium idor', 9: 'medium xxe',
         10: 'blind sqli', 11: 'DOM xss', 12: 'hard ssrf', 13: 'difficult idor', 14: 'difficult xxe',
         15: 'difficult sqli', 16: 'difficult xss', 17: 'extremely hard ssrf', 18: 'extemely difficult idor', 19: 'xxe',
         20: 'extremely difficult sqli', 21: 'highly sanitized xss', 22: 'ssrf', 23: 'idor', 24: 'xxe'}
random_vuln = randrange(25)
vuln = vulns[random_vuln]
print(vuln)

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
            "content": "Create an engaging, difficult, and highly complex single web page for people to test their skills."
                       f"That app will feature the vulnerability {vuln}"
                       "Make the web page attractive, colorful, with a narrative. "
                       "Make sure it is complex and extremely difficult and challenging, so that users can test their web app knowledge."
                       "Do not add hints for the puzzle in the HTML."
                       "I will run the exec function on your output, so do not add any unnecessary strings."

        }
    ],
    temperature=1,
    max_tokens=6000,
    top_p=1,
    frequency_penalty=0,
    presence_penalty=0
)
openai_content = openai_response.choices[0].message.content
print(openai_content)
openai_parsed_content = openai_content[10:-4]


def run_flask_app():
    exec(openai_parsed_content, globals())

# Determine the next file number
def get_next_file_number(base_name, extension):
    # Create a regex pattern to match the files
    pattern = rf"{re.escape(base_name)}_(\d+)\.{re.escape(extension)}"
    highest_number = 0

    # List all files in the current directory
    for filename in os.listdir(os.getcwd()):
        match = re.match(pattern, filename)
        if match:
            file_number = int(match.group(1))
            highest_number = max(highest_number, file_number)

    return highest_number + 1


# Get the next file number
base_name = "Room"
extension = "py"
next_file_number = get_next_file_number(base_name, extension)

# Create a new file name
new_file_name = f"{base_name}_{next_file_number}.{extension}"
new_file_path = os.path.join(os.getcwd(), new_file_name)

# Write the parsed content to the new file with UTF-8 encoding
with open(new_file_path, 'w', encoding='utf-8') as f:
    f.write(openai_parsed_content)


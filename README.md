# BugGPT

**BugGPT** is an open-source project that automatically generates vulnerable web applications for security practitioners to practice and enhance their web security skills. This project leverages OpenAI's GPT models to create random, engaging, and complex web pages containing various vulnerabilities, providing a challenge for those looking to test their hacking skills.

## Key Features

- **Vulnerability Variety**: Each generated web page contains a different vulnerability, ranging from SQL Injection, XSS, SSRF, IDOR, XXE, and more.
- **Automated Generation**: Web pages are generated automatically every 8 hours, ensuring a continuous flow of new challenges.
- **Realistic Scenarios**: The web apps created are designed to mimic real-world scenarios, offering a realistic testing environment.
- **Randomization**: Each vulnerability is selected at random, and the app is designed with a narrative, making it harder to determine the exact flaw.
- **Easy Integration**: With GitHub Actions in place, BugGPT continuously generates and pushes new vulnerable apps to the repository.
  
## Project Structure

- **page_generator.py**: The script responsible for generating new vulnerable web pages using OpenAI's API.
- **Rooms**: Each generated web page is stored as a `Room_x.py` file in this directory, where `x` is the room number.

## How it Works

1. **Vulnerability Generation**: BugGPT uses a predefined list of vulnerabilities and randomly selects one for each new web page.
2. **OpenAI Integration**: The page is generated by sending a prompt to the OpenAI GPT-4 model, instructing it to create a complex web app based on the chosen vulnerability.
3. **Flask Web App**: Each generated web page is a Python Flask app that you can run locally to explore the vulnerabilities.
4. **Automated Workflow**: A GitHub Action is scheduled to run every 8 hours, executing `page_generator.py`, which generates a new vulnerable app and commits it to the repository.

## How to Use BugGPT

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Trivulzianus/BugGPT.git
   cd BugGPT

2. **Install Dependencies: Ensure you have the necessary dependencies installed before running the script:**

    ```bash
    pip install -r requirements.txt
3. **Run Main.py, and select the room number you'd like to hack, or random**

   ```bash
   python3 main.py X (-> room number)
 4. **View the Vulnerable Web App:**
     After generating a new room, the Flask app will run locally. You can open your browser and visit the app to test your skills.

## GitHub Actions Workflow

The project is set up with a GitHub Actions workflow that automatically runs page_generator.py every 8 hours, pushing new vulnerable rooms to the repository. If you want to manually trigger the generation of a new room, you can do so from the GitHub Actions tab in the repository.

## Contributing

Contributions are welcome! If you'd like to contribute to BugGPT, feel free to fork the repository and submit a pull request.

    Fork the project.
    Create your feature branch (git checkout -b feature/new-feature).
    Commit your changes (git commit -m 'Add new feature').
    Push to the branch (git push origin feature/new-feature).
    Open a pull request.

## License

This project is licensed under the MIT License.

## Disclaimer

BugGPT is a project designed for educational purposes only. Please use responsibly. Do not deploy or use the generated web apps in any real-world scenario or environment where unauthorized access could occur.

# Happy Hacking with BugGPT!
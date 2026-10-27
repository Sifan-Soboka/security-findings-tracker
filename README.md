# Security Findings and Evidence Tracker

This is my second cybersecurity portfolio project. I built it to practise working with real vulnerability data and to understand how security teams can keep track of vulnerabilities and their remediation progress.

The project uses data from the National Vulnerability Database (NVD) and displays vulnerability findings in a dashboard. Instead of just looking at a list of CVEs, I wanted to make it easier to search for findings, understand their severity, and keep track of which ones still need attention.

## What it does

- Loads vulnerability information from an NVD JSON dataset.
- Displays CVE IDs, severity levels, CVSS scores, and priority scores.
- Allows users to search and filter vulnerability findings.
- Saves remediation statuses and notes in a local SQLite database.
- Exports findings as CSV or JSON files.
- Uses a risk-scoring system to help prioritise findings.

## Tools and technologies

- **Python** – main programming language
- **Streamlit** – dashboard interface
- **SQLite** – storing remediation statuses and notes
- **Pandas** – working with vulnerability data
- **NVD CVE data** – vulnerability dataset
- **Pytest** – testing the risk-scoring logic

## Running the project

You will need Python installed on your computer.

1. Clone or download this repository.
2. Open a terminal in the project folder.
3. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

4. Install the required packages:

   **Windows:**
   ```powershell
   .venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

5. Start the dashboard:

   ```powershell
   .venv\Scripts\python.exe -m streamlit run app.py
   ```

6. Open the local URL shown in the terminal.

The project uses a local database to save remediation updates, so those updates are stored on the computer running the application.

## What I learned

While building this project, I got more practice working with JSON data, Python modules, databases, and a dashboard interface. I also learned that getting data into an application is only one part of the work. It is important to handle the data properly and make the results useful to someone reviewing security findings.

I had to troubleshoot issues with the database and project setup along the way, which helped me understand how the different files work together.

## Current status

The dashboard is working, and I have tested the risk-scoring logic. I plan to continue improving the project as I learn more about vulnerability management and security operations.

## Disclaimer

This project is for learning and portfolio purposes. The priority score is a project-defined way of organising findings and should not be treated as a complete assessment of real-world risk. The dataset may not include every current vulnerability or the latest available information.

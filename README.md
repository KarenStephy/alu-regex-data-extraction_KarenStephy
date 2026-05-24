A Python program that reads a raw text file and pulls out useful data like emails, phone numbers, URLs, and credit card numbers — while blocking malicious content.

What the program does

Reads a messy text file (like a dump of support tickets)
Scans for dangerous content and removes it before doing anything else
Extracts four types of data using regex patterns
Saves the results as a clean JSON file


Project structure
alu-regex-data-extraction/
├── input/
│ └── raw-text.txt ← the text the program reads
├── src/
│ └── main.py ← the main program
├── output/
│ └── sample-output.json ← results (created automatically)
└── README.md

How to run it
Make sure you have Python 3 installed, then run:
bashcd src
python main.py
The output folder and JSON file are created automatically — you don't need to make them yourself.
Requirements

Python 3.8 or higher
No external libraries needed — uses only re, json, and os from the standard library

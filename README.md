
# PhishGuard - Phishing URL Detection System

## Project Overview

PhishGuard is a C++ based cybersecurity application
designed to analyze URLs and identify suspicious
characteristics commonly associated with phishing attacks.

The application uses heuristic-based detection
and a risk scoring mechanism to classify URLs.

## Features

- URL component extraction
- HTTP and HTTPS detection
- IP address detection
- Suspicious keyword detection
- URL length analysis
- Multiple hyphen detection
- Subdomain analysis
- Punycode detection
- Risk scoring from 0 to 100
- Low, Medium and High risk classification
- Interactive command-line interface

## Technologies

- C++
- C++17
- Standard Template Library (STL)
- Regular Expressions
- Object-Oriented Programming

## Project Structure

PhishGuard/
|
|-- src/
|   |-- main.cpp
|
|-- docs/
|   |-- Project_Documentation.pdf
|
|-- screenshots/
|   |-- execution.png
|
|-- README.md
|-- .gitignore
|-- LICENSE

## Installation

Install a C++ compiler such as GCC.

Compile the application:

g++ src/main.cpp -o PhishGuard.exe -std=c++17

Run:

.\PhishGuard.exe

## Risk Classification

0-19: Low Risk
20-49: Medium Risk
50-100: High Risk

## How It Works

The system analyzes URL characteristics and assigns
risk points to suspicious indicators.

The total score determines the risk category.

## Limitations

- Uses heuristic-based detection.
- Does not access live threat intelligence databases.
- Does not verify website ownership.
- Cannot guarantee that a website is safe.
- May produce false positives and false negatives.

## Future Improvements

- Integration with threat intelligence APIs.
- DNS and domain age analysis.
- Machine learning-based detection.
- Graphical user interface.
- CSV report generation.

## Disclaimer

This project is developed for educational and
cybersecurity learning purposes.

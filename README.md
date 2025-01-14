# Hamsterver

Hamsterver (i.e. public H1 Report Harvester) is a tool to download the latest disclosed reports from HackerOne and save them in markdown files in the `downloads/reports` directory for later LLM use.

## History

- The script was originally made to store the reports in MongoDB, but I converted it to markdown files for simplicity
- The new version was refactored and updated to use features from Python 3.12 with the use of Cursor IDE

## Installation

```bash
$ pip install -r requirements.txt
```

## Usage

To download the latest 5 reports, run:

```bash
$ python main.py 5
```

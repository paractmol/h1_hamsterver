# HackerOne Report Downloader

This script downloads the latest disclosed reports from HackerOne. The reports are saved in markdown files in the `downloads/reports` directory and can be added to the LLM for analysis and an easier way to search for vulnerabilities.

## History

- The script was originally made to store the reports in MongoDB, but I converted it to markdown files for simplicity
- The new version was refactored and updated to use features from Python 3.12 with the use of Cursor IDE

## Usage

To download the latest 5 reports, run:

```bash
$ python main.py 5
```

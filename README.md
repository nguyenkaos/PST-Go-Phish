# PST Go Phish
This is a Python 2.X script that extract mails from PST and OST file


## Usage
This script takes a PST or OST file as its input and an output directory. You can also supply a comma-delimited list of items to ignore (for example, you may want to ignore bounce lists or emails from known good senders). Alternatively, if the threshold switch is applied it will also flag potential throwaway emails (which could be related to phishing). The script creates a CSV file with a row for each potentially suspicious email found.
~~~
usage:
     parse_pstost.py PST_FILE OUTPUT_DIR

PST Go Phishing..

positional arguments:
  PST_FILE              File path to input PST/OST file
  OUTPUT_DIR            Output Dir for CSV
~~~

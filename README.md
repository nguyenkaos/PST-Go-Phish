# PST Go Phish
This is a Python 2.X script that interacts with PSTs and OSTs and identifies emails with mismatched sender / reply-to or return-path headers. It can also be used to identify messages from throwaway email accounts and unique links.
## Usage
This script takes a PST or OST file as its input and an output directory. You can also supply a comma-delimited list of items to ignore (for example, you may want to ignore bounce lists or emails from known good senders). Alternatively, if the threshold switch is applied it will also flag potential throwaway emails (which could be related to phishing). The script creates a CSV file with a row for each potentially suspicious email found.
~~~
python pst_go_phish.py -h
usage: pst_go_phish.py [-h] [-i IGNORE] [-t THRESHOLD] [-l LINKS]
                       PST_FILE OUTPUT_DIR

PST Go Phishing..

positional arguments:
  PST_FILE              File path to input PST file
  OUTPUT_DIR            Output Dir for CSV

optional arguments:
  -h, --help            show this help message and exit
  -i IGNORE, --ignore IGNORE
                        Comma-delimited acceptable emails to ignore e.g.
                        (bounce lists, etc.)
  -t THRESHOLD, --threshold THRESHOLD
                        Flag emails where sender has only sent N email to the
                        mailbox (default 1)
  -l LINKS, --links LINKS
                        Flag emails where the link has only sent/received N
                        times (default 1)

~~~

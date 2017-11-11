from __future__ import print_function
import csv
import os
import sys

"""
    PST-Go-Phish - Automatically find suspicious emails.
    Copyright (C) 2017  Preston Miller

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

def csv_writer(data, headers, output_directory, name=None):
    if name is None:
        name = "Go_Phish_Report.csv"

    if sys.version_info > (3, 0):
        with open(os.path.join(output_directory, name), "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(data)
    else:
        try:
	    import unicodecsv
        except ImportError:
	    print("[+] Install the unicodecsv module to write the CSV report")
	    sys.exit(1)

        with open(os.path.join(output_directory, name), "wb") as csvfile:
            writer = unicodecsv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(data)

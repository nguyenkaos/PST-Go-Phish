import argparse
import os
import pypff
import sys
import unicodecsv as csv


message_list = []
messages = 0
compared_messages = 0
suspicious_messages = 0
ignored_messages = 0

def main(pst_file, output_dir, ig):
	print "[+] Accessing {} PST file..".format(pst_file)
	pst = pypff.open(pst_file)
	root = pst.get_root_folder()
	print "[+] Traversing PST folder structure.."
	if ig is not None:
		ignore = [x.strip().lower() for x in ig.split(',')]
	else:
		ignore = []
	recursePST(root, ignore)
	print "[+] Identified {} messages..".format(messages)
	print "[+] Compared {} messages. Messages not compared were missing a FROM header or both Reply-To and Return-Path".format(compared_messages)
	print "[+] Ignored {} comparable messages".format(ignored_messages)
	print "[+] Identified {} suspicious messages..".format(suspicious_messages)
	csvWriter(output_dir)


def recursePST(base, ignore):
	for folder in base.sub_folders:
		if folder.number_of_sub_folders:
			recursePST(folder, ignore)
		processMessages(folder, ignore)


def processMessages(folder, ignore):
	global messages
	print "[+] Processing Folder: {}".format(folder.name)
	for message in folder.sub_messages:
		eml_from, replyto, returnpath = ("", "", "")
		messages += 1
		try:
			headers = message.get_transport_headers().splitlines()
		except AttributeError:
			# No email header
			continue
		for header in headers:
			if header.strip().lower().startswith("from:"):
				eml_from = header.strip().lower()
			elif header.strip().lower().startswith("reply-to:"):
				replyto = header.strip().lower()
			elif header.strip().lower().startswith("return-path:"):
				returnpath = header.strip().lower()
		if eml_from == "" or (replyto == "" and returnpath == ""):
			# No FROM value or no Reply-To / Return-Path value
			continue
		
		compareMessage(folder, message, eml_from, replyto, returnpath, ignore)  



def compareMessage(folder, msg, eml_from, reply, return_path, ignore):
	global message_list, compared_messages, suspicious_messages, ignored_messages
	compared_messages += 1
	reply_email = ''
	return_email = ''
	reply_bool = False
	return_bool = False
	suspicious = False
	found_suspicious = ""
	from_email, from_domain = emailExtractor(eml_from)
	if reply != "":
		reply_bool = True
		reply_email, reply_domain = emailExtractor(reply)
	if return_path != "":
		return_bool = True
		return_email, return_domain = emailExtractor(return_path)
	if return_bool is True:
		if from_domain != False and return_domain != False:
			for igno in ignore:
				if igno in return_email:
					ignored_messages += 1
					return
			if from_domain != return_domain:
				suspicious = True
				found_suspicious = "Return-Path"

	if reply_bool is True:
		if from_domain != False and reply_domain != False:
			for igno in ignore:
				if igno in reply_email:
					ignored_messages += 1
					return
			if from_domain != reply_domain:
				suspicious = True
				if found_suspicious == "Return-Path":
					found_suspicious = "Both"
				else:
					found_suspicious = "Reply-To"
	
	if suspicious is True:
		suspicious_messages += 1
		message_list.append([folder.name, msg.get_subject(), msg.get_sender_name(), msg.number_of_attachments, from_email, return_email, reply_email, found_suspicious])


def emailExtractor(item):
	if "<" in item:
		start = item.find("<") + 1
		stop = item.find(">")
		email = item[start:stop]
	else:
		email = item.split(":")[1].strip()
	if "@" not in email:
		domain = False
	else:
		domain = email.split("@")[1]
	return email, domain


def csvWriter(output_dir):
	global message_list
	headers = ["Folder", "Subject", "Sender", "Attachments", "From Email", "Return-Path", "Reply-To", "Flag"]
	with open(os.path.join(output_dir, "go_phish.csv"), "wb") as csvfile:
		csv_writer = csv.writer(csvfile)
		csv_writer.writerow(headers)
		csv_writer.writerows(message_list)

if __name__ == '__main__':
	# Command-line Argument Parser
	parser = argparse.ArgumentParser(description="PST Go Phishing..")
	parser.add_argument("PST_FILE", help="File path to input PST file")
	parser.add_argument("OUTPUT_DIR", help="Output Dir for CSV")
	parser.add_argument("-i", "--ignore", help="Comma-delimited acceptable emails to ignore e.g. (bounce lists, etc.)")
	args = parser.parse_args()
	
	if not os.path.exists(args.OUTPUT_DIR):
		os.makedirs(args.OUTPUT_DIR)
	
	if os.path.exists(args.PST_FILE) and os.path.isfile(args.PST_FILE):
		main(args.PST_FILE, args.OUTPUT_DIR, args.ignore)
	else:
		print "[-] Input PST {} does not exist or is not a file".format(args.PST_FILE)
		sys.exit(1)

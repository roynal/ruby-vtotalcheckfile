vtotalcheckfile - Command Line VirusTotal File Scanner
==

This simple command line utility will upload a file to VirusTotal and check it for viruses, malware and trojans.


Features
---

* Checks to see if a report already exists for the file before uploading to save time.
* Force upload a file even if a report aleady exists.
* Checks for newly generated report immediately after upload and at specified intervals until report is available.

RubyGem Requirements
---

* json
* rdoc
* rest-client
* term-ansicolor

* public API key from virustotal.com

Installation
---

**RubyGems**

    gem install json rdoc rest-client term-ansicolor

**Latest from sources***

    git clone git://github.com/hink/ruby-vtotalcheckfile.git
    cd ruby-vtotalcheckfile
    # edit vtotalcheckfile and insert your VirusTotal API key (line 85)
    ./vtotalcheckfile -h

## Options
	
	-f, --force         Force VirusTotal to re-analyze your file
	-h, --help          Displays help message
	-i, --interval      Check Interval in seconds (min 15)
	-v, --version       Display the version, then exit
	-V, --verbose       Verbose
	
## Usage

	vtotalcheckfile [-fhvV][-i checkInterval] filepath
	
## Examples

	vtotalcheckfile ~/document.pdf
	
	vtotalcheckfile -f -i 15 /home/user1/document.doc

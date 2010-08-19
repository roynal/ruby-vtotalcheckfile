#!/usr/bin/env ruby 

# == Synopsis 
#   Tests a file for infections using VirusTotal
#
# == Examples
#   This will upload document.pdf to VirusTotal and check it for viruses/trojans.
#     vtotalcheckfile ~/document.pdf
#
#   Other examples:
#     vtotalcheckfile -i 15 /tmp/document.doc
#
# == Usage 
#   vtotalcheckfile [-fhvV][-i checkInterval] filePath
#
#   For help use: vtotalcheckfile -h
#
# == Options
#   -f, --force         Force VirusTotal to re-analyze your file
#   -h, --help          Displays help message
#   -i, --interval      Check Interval in seconds (min 15)
#   -v, --version       Display the version, then exit
#   -V, --verbose       Verbose
#
# == Author
#   Chris Hinkley
#
# == Copyright
#   Copyright (c) 2009 Chris Hinkley. Licensed under the WTFPL License:
#   http://sam.zoy.org/wtfpl/

require 'rubygems'
require 'optparse' 
require 'json'
require 'rdoc/usage'
require 'ostruct'
require 'date'
require 'rest-client'
require 'digest/md5'

require 'term/ansicolor'

include Term::ANSIColor

class App
  VERSION = '0.0.1'
  
  def onoe error
    return if @options.quiet
    lines = error.to_s.split'\n'
    puts "#{red}#{underline}Error#{reset}: #{lines.shift}"
    puts *lines unless lines.empty?
  end

  def opoo warning
    return if @options.quiet
    puts "#{yellow}#{underline}Warning#{reset}: #{warning}"
  end

  def ohai title, *sput
    return if @options.quiet
    title = title.to_s[0, `/usr/bin/tput cols`.strip.to_i-4]
    puts "#{blue}==>#{white}#{bold} #{title}#{reset}"
    puts *sput unless sput.empty?
  end

  def okai title, *sput
    return if @options.quiet
    title = title.to_s[0, `/usr/bin/tput cols`.strip.to_i-4]
    puts "#{blue}  : #{white}#{bold}#{title}#{reset}"
    puts *sput unless sput.empty?
  end

  def oyay message
    return if @options.quiet
    puts "#{green}#{bold}  Done#{reset}: #{message}"
  end
  
  attr_reader :options

  def initialize(arguments, stdin)
    @arguments = arguments
    @stdin = stdin
    
    @virusTotalAPIKey = ""
    @filePath = ''
    @resource = ''
    @uploadTIme = ''
    
    # Set defaults
    @options = OpenStruct.new
    @options.verbose = false
    @options.quiet = false
    @options.interval = 20
    @options.force = false
  end

  # Parse options, check arguments, then process the command
  def run
        
    if parsed_options? && arguments_valid? 
      
      puts "Start at #{DateTime.now}\n\n" if @options.verbose
      
      output_options if @options.verbose # [Optional]
            
      process_arguments            
      process_command
      
      puts "\nFinished at #{DateTime.now}" if @options.verbose
      
    else
      output_usage
    end
      
  end
  
  protected
  
    def parsed_options?
      
      # Specify options
      opts = OptionParser.new 
      opts.on('-v', '--version')    { output_version ; exit 0 }
      opts.on('-h', '--help')       { output_help }
      opts.on('-V', '--verbose')    { @options.verbose = true }  
      opts.on('-q', '--quiet')      { @options.quiet = true }
      
      opts.on('-f', '--force')      { @options.force = true }
      opts.on('-i seconds', '--interval seconds') do |interval|
        interval = 15 if interval < 15
        @options.interval = interval
      end
                  
      opts.parse!(@arguments) rescue return false
      
      process_options
      true      
    end

    # Performs post-parse processing on options
    def process_options
      @options.verbose = false if @options.quiet
    end
    
    def output_options
      puts "Options:\n"
      
      @options.marshal_dump.each do |name, val|        
        puts "  #{name} = #{val}"
      end
    end

    # True if required arguments were provided
    def arguments_valid?
      # TO DO - implement your real logic here
      true if @arguments.length == 1
    end
    
    # Setup the arguments
    def process_arguments
      @filePath = @arguments[0]
      if !File.file?(@filePath)
        onoe "File does not exist!"
        exit 1
      end
      if File.size(@filePath) > 20971520
        onoe "File is larger than 20MB!"
        exit 1        
      end
    end
    
    def output_help
      output_version
      RDoc::usage() #exits app
    end
    
    def output_usage
      RDoc::usage('usage') # gets usage from comments above
    end
    
    def output_version
      puts "#{File.basename(__FILE__)} version #{VERSION}"
    end
    
    def process_command      
      if @virusTotalAPIKey == ''
        onoe "No VirusTotal API key Found! Get one at www.VirusTotal.com."
        exit 1
      end
      
      if !@options.force
        ohai "Checking to see if file exists on VirusTotal"
        okai "MD5: " + getMD5(@filePath) if @options.verbose
        return if reportExists(@filePath)
      end
      ohai "Attempting to upload" + @filePath + " (" + getFileSize(@filePath) + ") to VirusTotal"
      sendFile(@filePath)
      ohai "Attempting to retrieve report"
      okai "Waiting #{@options.interval} seconds before attempting to retrieve report."
      sleep @options.interval
      while !getReport(@filePath,false)
        sleep @options.interval
      end
    end

    def process_standard_input
      input = @stdin.read      

      # @stdin.each do |line| 
      #  # TO DO - process each line
      #end
    end
    
    # ===========================
    
    def reportExists(filePath)
      return getReport(filePath,true)
    end
    
    def sendFile(filepath)
      @uploadTime = DateTime.now
      response = RestClient.post 'https://www.virustotal.com/api/scan_file.json', :file => File.new(filepath, 'rb'), :key => @virusTotalAPIKey
      result = JSON.parse(response.to_str)
      case result["result"]
        when 1
          oyay "File Uploaded successfully!"
          oyay "ScanID: " + result["scan_id"].to_s if @options.verbose
        else        
          onoe "Error uploding file."
          exit 1
      end
    end
    
    def getReport(filePath, isInitial)
      response = RestClient.post 'https://www.virustotal.com/api/get_file_report.json', :resource => getMD5(@filePath), :key => @virusTotalAPIKey
      result = JSON.parse(response.to_str)
      case result["result"]
        when 1
          if isInitial
            okai "File with same MD5 already exists on VirusTotal!"
          else
            if @options.force
              return false if @uploadTime > DateTime.parse(result["report"][0].to_s)
            end
            oyay "Report is ready!"
          end
          printReport(result)
          return true
        else
          if isInitial
            okai "File is new to VirusTotal."
          else
            okai "Report is not ready yet. We will check again in #{@options.interval} seconds."
          end
      end
      return false
    end
    
    def printReport(data)
      puts "-------------------"
      puts "Report for #{@filePath}"
      puts "MD5: " + getMD5(@filePath) if @options.verbose
      puts "Report Date: #{data["report"][0].to_s}"
      puts "-------------------"
      bad = 0
      scanners = data["report"][1].each {|scanner|
        name = scanner[0].to_s
        result = scanner[1].to_s
        if result == ''
          # Clean
          puts "#{green}#{name} : #{reset}Clean"
        else
          # Infected
          puts "#{red}#{name} : #{reset}#{result}"
          bad = bad + 1
        end
      }
      puts "-------------------"
      puts " " + bad.to_s + " / " + data["report"][1].length.to_s
      puts "-------------------" 
    end
    
    def getFileSize(filePath)
      size = File.size(@filePath)
      sizeStr = '0'
      case size
        when size > 1024
          # KB
          sizeStr = (size/1024).to_s + "KB"
        when size > 1048576
          # MB
          sizeStr = (size/1048576).to_s + "MB"
        else
          # B
          sizeStr = size.to_s + "B"
      end
      
      return sizeStr
    end
    
    def getMD5(filePath)
        @resource = Digest::MD5.hexdigest(File.read(@filePath)) if @resource == ''
        return @resource
    end
    
end

# Create and run the application
app = App.new(ARGV, STDIN)
app.run

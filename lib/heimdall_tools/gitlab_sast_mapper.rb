require 'json'
require 'csv'
require 'heimdall_tools/hdf'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

CWE_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'cwe-nist-mapping.csv')

# set impact/severity mapping
IMPACT_MAPPING = {
  info: 0.0,
  unknown: 0.1,
  low: 0.3,
  medium: 0.5,
  high: 0.7,
  critical: 0.9
}.freeze

DEFAULT_NIST_TAG = %w{SA-11 RA-5}.freeze

# Loading spinner sign
$spinner = Enumerator.new do |e|
  loop do
    e.yield '|'
    e.yield '/'
    e.yield '-'
    e.yield '\\'
  end
end

module HeimdallTools
  class GitlabSastMapper
    def initialize(sast_json, _name = nil, verbose = false)
      #set json file and verbosity parameters
      @sast_json = sast_json
      @verbose = verbose

      begin
        # load CWE mapping
        @cwe_nist_mapping = parse_mapper
        # parse JSON from SAST JSON input file
        @sastresults = JSON.parse(sast_json)
      rescue StandardError => e
        raise "Invalid Gitlab SAST JSON file provided Exception: #{e}" 
      end
    end

    def finding(vulnerability)
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = []
      finding['code_desc'] << "id : #{vulnerability['id']}"
      #finding['code_desc'] << "category : #{vulnerability['category']}"
      #finding['code_desc'] << "fixed_versions : #{vulnerability['component_versions']['fixed_versions']}"
      #finding['code_desc'] << "issue_type : #{vulnerability['issue_type']}"
      #finding['code_desc'] << "issue_type : #{vulnerability['issue_type']}"
      finding['code_desc'] << "location : #{vulnerability['location']['file']} : lines #{vulnerability['location']['start_line']}-#{vulnerability['location']['end_line']}"
      finding['code_desc'] = finding['code_desc'].join("\n")
      finding['run_time'] = NA_FLOAT
      finding['start_time'] = vulnerability['start_time'] || ""
      [finding]
    end

    def format_control_desc(vulnerability)
      text = []
      info = vulnerability['description']
      text << info['description'].to_s
      text << "cves: #{info['cves']}" unless info['cves'].nil?
      text.join('<br>')
    end

    def nist_tag(cweid)
      entries = @cwe_nist_mapping.select { |x| cweid.include?(x[:cweid].to_s) && !x[:nistid].nil? }
      tags = entries.map { |x| x[:nistid] }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def parse_identifiers(identifier, ref)
      # Extracting id number from reference style CWE-297
      identifier['name'][ref].map { |e| e.split("#{ref}-")[1] }
    rescue StandardError
      []
    end

    def impact(severity)
      IMPACT_MAPPING[severity.downcase.to_sym]
    end

    def parse_mapper
      csv_data = CSV.read(CWE_NIST_MAPPING_FILE, **{encoding: 'UTF-8',
                                                    headers: true,
                                                    header_converters: :symbol,
                                                    converters: :all })
      csv_data.map(&:to_hash)
    end

    def desc_tags(data, label)
      { data: data || NA_STRING, label: label || NA_STRING }
    end

    # Xray report could have multiple vulnerability entries for multiple findings of same issue type.
    # The meta data is identical across entries
    # method collapse_duplicates return unique controls with applicable findings collapsed into it.
    def collapse_duplicates(controls)
      unique_controls = []

      controls.map { |x| x['id'] }.uniq.each do |id|
        collapsed_results = controls.select { |x| x['id'].eql?(id) }.map { |x| x['results'] }
        unique_control = controls.find { |x| x['id'].eql?(id) }
        unique_control['results'] = collapsed_results.flatten
        unique_controls << unique_control
      end
      unique_controls
    end

    def to_hdf
      controls = []
      vulnerability_count = 0
      @sastresults['vulnerabilities'].uniq.each do |vulnerability|
        printf("\rProcessing: %s", $spinner.next)

        vulnerability_count +=1
        item = {}
        item['id']                 = OpenSSL::Digest::MD5.digest(vulnerability['name'].to_s).unpack1('H*').to_s
        item['title']              = vulnerability['name'].to_s
        item['desc']               = vulnerability['description']
        item['impact']             = impact(vulnerability['severity'].to_s)
        item['source_location']    = "" #"#{vulnerability['location']['file']} : lines #{vulnerability['location']['start_line']}-#{vulnerability['location']['end_line']}"
        item['code']               = ""
        item['results']            = finding(vulnerability)

        item['tags']               = {}
        # populate identifiers - cve, cwe, osvdb, usn or analyzer-dependent type (gemnasium or eslint)
        # may contain multiple identifiers for same type - process by type and parse all appropriate entries
        vulnerability["identifiers"].map {|id| id["type"]}.uniq.each do |type|
          # populate combined entry for each unique type
          vulnerability["identifiers"].select {|id| 
            if id["type"]==type
              # map appropriately from NIST mappings
              item['tags'][type].nil?  ? item['tags'][type] = [id["name"]] : item['tags'][type] << id["name"]
            end
          }
        end

        controls << item
      end

      controls = collapse_duplicates(controls)
      results = HeimdallDataFormat.new(profile_name: 'Gitlab SAST Scan',
                                       version: @sastresults['version'],
                                       title: "Gitlab SAST Scan - #{@sastresults['scan']['scanner']['name']} #{@sastresults['scan']['scanner']['version']}",
                                       summary: 'Continuous Security and Universal Artifact Analysis',
                                       controls: controls)
      results.to_hdf
    end
  end
end

$LOAD_PATH.unshift(File.expand_path(__dir__))
require 'heimdall_tools/version'

module HeimdallTools
  autoload :Help, 'heimdall_tools/help'
  autoload :Command, 'heimdall_tools/command'
  autoload :CLI, 'heimdall_tools/cli'
  autoload :FortifyMapper, 'heimdall_tools/fortify_mapper'
  autoload :ZapMapper, 'heimdall_tools/zap_mapper'
  autoload :SonarQubeMapper, 'heimdall_tools/sonarqube_mapper'
  autoload :BurpSuiteMapper, 'heimdall_tools/burpsuite_mapper'
  autoload :NessusMapper, 'heimdall_tools/nessus_mapper'
  autoload :SnykMapper, 'heimdall_tools/snyk_mapper'
  autoload :NiktoMapper, 'heimdall_tools/nikto_mapper'
  autoload :JfrogXrayMapper, 'heimdall_tools/jfrog_xray_mapper'
end

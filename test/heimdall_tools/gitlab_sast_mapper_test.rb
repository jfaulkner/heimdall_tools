require 'minitest/autorun'
require './lib/heimdall_tools/gitlab_sast_mapper'

class GitlabSastMapperTest < Minitest::Test
  def test_it_works
    hdf = HeimdallTools::GitlabSastMapper.new(File.read(File.join(File.dirname(__FILE__), 'gl-sast-report.json'))).to_hdf
    assert hdf
    puts hdf
    assert hdf['controls']
  end
end
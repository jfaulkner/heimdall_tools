require 'minitest/autorun'
require 'json'
require './lib/heimdall_tools/gitlab_sast_mapper'

class GitlabSastMapperTest < Minitest::Test
  def test_it_works
    hdf = HeimdallTools::GitlabSastMapper.new(File.read(File.join(File.dirname(__FILE__), 'gl-sast-report.json'))).to_hdf
    #puts hdf
    assert hdf != nil
    results = JSON.parse(hdf)
    assert results["profiles"][0]["controls"].size > 0
  end
end
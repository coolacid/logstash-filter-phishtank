# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "json"

# This example filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::VirusTotal < LogStash::Filters::Base

  config_name "phishtank"
  
  # Your VirusTotal API Key
  config :apikey, :validate => :string
  
  # For filed containing the item to lookup. This can point to a field ontaining a File Hash or URL
  config :field, :validate => :string, :required => true

  # Where you want the data to be placed
  config :target, :validate => :string, :default => "phishtank"

  public
  def register
    require "faraday"
  end # def register

  public
  def filter(event)

    url = "http://checkurl.phishtank.com/checkurl/"
    response = Faraday.post url, { :url => event[@field], :apikey => @apikey, :format => "json" }
    result = JSON.parse(response.body)
    event[@target] = result

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Example

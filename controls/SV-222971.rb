control 'SV-222971' do
  title 'Tomcat servers must mutually authenticate proxy or load balancer connections.'
  desc 'Tomcat servers are often placed behind a proxy when exposed to both trusted and untrusted networks. This is done for security and performance reasons.  Tomcat does provide an HTTP server that can be configured to make hosted applications available to clients directly. However, this HTTP server has performance limitations and is not intended to be used on an enterprise scale. Exposing this service to untrusted networks also violates the layered security model and creates elevated risk of attack. To address these issues, a proxy or load balancer can be placed in front of the Tomcat server. To ensure the proxied connection is not spoofed, SSL mutual authentication must be employed between Tomcat and the proxy.

Not all Tomcat systems will have an RMF system categorization that warrants mutual authentication protections. The site must determine if mutual authentication is warranted based on their system RMF categorization and data protection requirements. If the site determines that MA is not a requirement, they can document a risk acceptance for not mutually authenticating proxy or load balancer connections due to operational issues, or when the RMF system categorization does not warrant the added level of protection.'
  desc 'check', 'Review system security plan and/or system architecture documentation and interview the system admin. Identify any proxy servers or load balancers that provide services for the Tomcat server. If there are no load balancers or proxies in use, this is not a finding.

If there is a documented risk acceptance for not mutually authenticating proxy or load balancer connections due to operational issues, or RMF system categorization this is not a finding.

Using the aforementioned documentation, identify each Tomcat IP address that is served by a load balancer or proxy.

From the Tomcat server as a privileged user, review the $CATALINA_BASE/conf/server.xml file. Review each <SSLHostConfig> element for the address setting and the certificationVerification.

sudo grep -i -B1 -A5 connector $CATALINA_BASE/conf/server.xml

If a connector has a configured IP address that is proxied or load balanced and the clientAuth setting is not "true", this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user, edit the $CATALINA_BASE/conf/server.xml file.

Modify each <SSLHostConfig> element where the IP address is behind a proxy or load balancer.

Set certificationVerification="true", identify the applications that are associated with the connector, and edit the associated web.xml files. Ensure the <auth-method> is set to CLIENT-CERT.'
  impact 0.5
  tag check_id: 'C-24643r1264562_chk'
  tag severity: 'medium'
  tag gid: 'V-222971'
  tag rid: 'SV-222971r1264563_rule'
  tag stig_id: 'TCAT-AS-000800'
  tag gtitle: 'SRG-APP-000219-AS-000147'
  tag fix_id: 'F-24632r1135499_fix'
  tag 'documentable'
  tag legacy: ['SV-111465', 'V-102525']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  load_balancer = input('behind_a_loadbalancer')
  ma = input('mutual_authentication_not_required')

  if !load_balancer || ma
    impact 0.0
    desc 'caveat', 'The service is not behind a proxy or load balacner or documented risk acceptance of not mutually authenticating
    proxy or load balancer connections. This is not a finding.'

    describe 'Server is not behind a load balancer or risk has been accepted' do
      skip 'The server is not behind a load balancer or proxy or the SSP indicates that the risk has been accepted of not mutually authenticating connections'
    end
  else
    catalina_base = input('catalina_base')
    tomcat_server_file = xml("#{catalina_base}/conf/server.xml")
    # V3R5 moved the setting from Connector clientAuth to SSLHostConfig (DISA writes
    # "certificationVerification"; Tomcat's attribute is certificateVerification). Every host a
    # non-loopback connector serves must require client certificates, each checked on its own; an
    # unset attribute means Tomcat's 'none'. The Connector's clientAuth / SSLVerifyClient configure
    # the default host (defaultSSLHostConfigName), which Tomcat creates from them when no nested
    # SSLHostConfig has that name. A Connector without an address listens on all addresses.
    required = /\A(true|yes|require|required)\z/i
    loopback = ['127.0.0.1', '::1']
    checked = 0
    connector_count = tomcat_server_file['//Connector'].count

    (1..connector_count).each do |i|
      conn_path = "/descendant::Connector[#{i}]" # document order; //Connector[i] indexes within each Service
      address = tomcat_server_file["#{conn_path}/@address"].first
      next if loopback.include?(address)

      checked += 1
      label = "Connector #{address || '(all addresses)'}:#{tomcat_server_file["#{conn_path}/@port"].first}"
      legacy = tomcat_server_file["#{conn_path}/@clientAuth"] + tomcat_server_file["#{conn_path}/@SSLVerifyClient"]
      legacy = legacy.find { |v| v !~ required } || legacy.first # any non-requiring alias wins
      default_host = tomcat_server_file["#{conn_path}/@defaultSSLHostConfigName"].first || '_default_'
      host_names = []

      (1..tomcat_server_file["#{conn_path}/SSLHostConfig"].count).each do |j|
        host_path = "#{conn_path}/SSLHostConfig[#{j}]"
        host_name = tomcat_server_file["#{host_path}/@hostName"].first || '_default_'
        host_names << host_name
        verification = tomcat_server_file["#{host_path}/@certificateVerification"].first
        verification ||= legacy if host_name == default_host
        describe "#{label} SSLHostConfig #{host_name} certificateVerification" do
          subject { verification.to_s }
          it { should match required }
        end
      end

      next if host_names.include?(default_host)

      describe "#{label} default host #{default_host} (Connector clientAuth / SSLVerifyClient)" do
        subject { legacy.to_s }
        it { should match required }
      end
    end

    if checked.zero?
      describe 'Connectors listening on a non-loopback address' do
        subject { checked }
        it { should eq 0 }
      end
    end
  end
end

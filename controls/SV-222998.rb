control 'SV-222998' do
  title 'Changes to $CATALINA_HOME/bin/ folder must be logged.'
  desc 'The $CATALINA_HOME/bin folder contains startup and control scripts for the Tomcat Catalina server. To provide forensic evidence in the event of file tampering, changes to content in this folder must be logged. For Linux OS flavors other than Ubuntu, use the relevant OS commands. This can be done on the Ubuntu OS via the auditctl command. Using the -p wa flag set the permissions flag for a file system watch and logs file attribute and content change events into syslog.'
  desc 'check', 'Check the audit rules for the Tomcat folders. Run the following command from the Tomcat server as a privileged user:

sudo auditctl -l | grep $CATALINA_HOME/bin

If the results do not include "-w $CATALINA_HOME/bin -p wa -k tomcat" or if there are no results, this is a finding.'
  desc 'fix', %q(From the Tomcat server as a privileged user:

1. Identify the home folder for the Tomcat server:
#grep -i -- 'catalina_home\\|catalina_base' /etc/systemd/system/tomcat.service

Lines similar to the following should be returned:
Environment="CATALINA_HOME=/opt/tomcat"
Environment="CATALINA_BASE=/opt/tomcat"
where /opt/tomcat in the example will be referred to as <homefolderpath>

2. Add rules to a rules file. These files will typically be /etc/audit/rules.d/audit.rules or stig.rules. Open the rules file <rulesfile> in a text editor.

3. Alter or add the following line to the rules file, replacing <homefolderpath> with the actual path. (e.g., /opt/tomcat):
-w <homefolderpath>/bin -p wa -k tomcat

4. Load the rules, replacing <rulesfile> with the actual filename (e.g., audit.rules):
#auditctl -R <rulesfile>

5. Make the rules persistent:
#augenrules --load)
  impact 0.5
  tag check_id: 'C-24670r1192753_chk'
  tag severity: 'medium'
  tag gid: 'V-222998'
  tag rid: 'SV-222998r1264587_rule'
  tag stig_id: 'TCAT-AS-001590'
  tag gtitle: 'SRG-APP-000504-AS-000229'
  tag fix_id: 'F-24659r1193095_fix'
  tag 'documentable'
  tag legacy: %w[SV-111519 V-102579]
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  only_if('This control is Not Applicable to containers', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  catalina_base = input('catalina_base')
  desired_result = "-w #{catalina_base}/bin -p wa -k tomcat"

  describe auditd do
    its('lines') { should include desired_result }
  end
end

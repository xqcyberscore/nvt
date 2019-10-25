###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Server Administration Unauthorized Access Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111013");
  script_version("2019-10-25T10:01:14+0000");
  script_cve_id("CVE-2010-4094", "CVE-2009-3548", "CVE-2009-4189", "CVE-2009-3099", "CVE-2009-3843",
                "CVE-2009-4188", "CVE-2010-0557");
  script_bugtraq_id(44172, 36954, 79264, 79351, 37086, 36258, 38084);
  script_name("Apache Tomcat Server Administration Default/Hardcoded Credentials");
  script_tag(name:"last_modification", value:"2019-10-25 10:01:14 +0000 (Fri, 25 Oct 2019)");
  script_tag(name:"creation_date", value:"2015-04-10 15:00:00 +0200 (Fri, 10 Apr 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-10-214/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-09-085/");

  script_tag(name:"solution", value:"Change the password to a strong one or remove the user from tomcat-users.xml.");

  script_tag(name:"summary", value:"The Apache Tomcat Server Administration is using default or known
  hardcoded credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  script_timeout(600);

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

req = http_get( item:"/admin/", port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

cookie = eregmatch( pattern:"JSESSIONID=([0-9A-Z]+);", string:res );
if( isnull( cookie[1] ) )
  exit( 0 );

if( "Tomcat Server Administration" >!< res )
  exit( 0 );

# nb: Keep in sync with 2012/gb_tomcat_default_credentials.nasl
credentials = make_list( "admin:admin", # Taken from various example files / documentations as well as from https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown and https://www.ikkisoft.com/stuff/TomcatSec_LucaCarettoni.pdf
                         "admin:changethis",
                         "admin:password",
                         "admin:Password1",
                         "admin:password1",
                         "admin:vagrant",
                         "both:tomcat",
                         "manager:manager",
                         "password:password",
                         "role:changethis",
                         "role1:role1",
                         "role1:tomcat",
                         "role1:tomcat7",
                         "root:changethis",
                         "root:password",
                         "root:Password1",
                         "root:password1",
                         "root:r00t",
                         "root:root",
                         "root:toor",
                         "scott:tiger", # Oracle freaks
                         "tomcat:admin",
                         "tomcat:changethis",
                         "tomcat:j5Brn9", # Sun Solaris installation
                         "tomcat:none",
                         "tomcat:password",
                         "tomcat:Password1",
                         "tomcat:password1",
                         "tomcat:tomcat",
                         "ADMIN:ADMIN", # https://nvd.nist.gov/vuln/detail/CVE-2010-4094
                         "admin:none", # https://nvd.nist.gov/vuln/detail/CVE-2009-3548
                         "admin:tomcat", # https://github.com/seshendra/vagrant-ubuntu-tomcat7/blob/abd0a6c9cf08f8db642bde33ce7491259247ce18/manifests/default.pp#L49-L50
                         "ovwebusr:OvW*busr1", # https://nvd.nist.gov/vuln/detail/CVE-2009-4189, https://nvd.nist.gov/vuln/detail/CVE-2009-3099 and https://nvd.nist.gov/vuln/detail/CVE-2009-3843
                         "j2deployer:j2deployer", # https://nvd.nist.gov/vuln/detail/CVE-2009-4188
                         "tomcat:s3cret", # https://github.com/apache/tomcat/blob/2b8f9665dbfb89c78878784cd9b63d2b976ba623/webapps/manager/WEB-INF/jsp/403.jsp#L66
                         "cxsdk:kdsxc", # https://nvd.nist.gov/vuln/detail/CVE-2010-0557
                         "xampp:xampp", # XAMPP from https://www.apachefriends.org/index.html
                         "QCC:QLogic66", # QLogic QConvergeConsole from http://www.qlogic.com/
                         "root:owaspbwa", # OWASP Broken Web Applications Project
                         "fhir:FHIRDefaultPassword" ); # HAPI FHIR from http://hapifhir.io/

vuln = FALSE;
report = "";

host = http_host_name( port:port );
useragent = http_get_user_agent();
foreach credential( credentials ) {

  user_pass = split( credential, sep:":", keep:FALSE );

  user = chomp( user_pass[0] );
  pass = chomp( user_pass[1] );

  if( tolower( pass ) == "none" ) pass = "";

  data = string( "j_username=" + user + "&j_password=" + pass );
  len = strlen( data );

  req = 'POST /admin/j_security_check;jsessionid=' + cookie[1] + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Referer: http://' + host + '/admin/\r\n' +
        'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
        'Connection: keep-alive\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res =~ "^HTTP/1\.[01] 302" && "/admin/" >< res ) {

    req = 'GET /admin/ HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Referer: http://' + host + '/admin/\r\n' +
          'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
          'Connection: keep-alive\r\n' +
          '\r\n';
    res = http_keepalive_send_recv( port:port, data:req );

    req = 'GET /admin/banner.jsp HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Referer: http://' + host + '/admin/\r\n' +
          'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
          'Connection: keep-alive\r\n' +
          '\r\n';
    res = http_keepalive_send_recv( port:port, data:req );

    if( "/admin/commitChanges.do" >< res ) {
      report += "It was possible to login into the Tomcat Server Administration at " + report_vuln_url( port:port, url:"/admin/index.jsp", url_only:TRUE ) + ' using user "' + user + '" with password "' + pass + '"';
      vuln = TRUE;
    }
  }
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_skybox_security_appliance_info_disclosure_05_14.nasl 2780 2016-03-04 13:12:04Z antu123 $
#
# Skybox Security Appliance Multiple Information Disclosure Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.105027";

tag_insight = "A vulnerability has been found in some Skybox View Appliances' Admin
interfaces which would allow a potential malicious party to bypass
the authentication mechanism and obtain read-only access to the
appliance's administrative menus.";

tag_impact = "This would allow the malicious party to read system-related information
such as interface names, IP addresses and the appliance status.";

tag_affected = "Skybox View Appliances with ISO versions: 6.3.33-2.14, 6.3.31-2.14,
6.4.42-2.54, 6.4.45-2.56, 6.4.46-2.57";

tag_summary = "Skybox Security Appliance is prone to multiple information-disclosure vulnerabilities.";
tag_solution = "Please refer to the vendor security advisor: Security Advisory 2014-3-25-1";
tag_vuldetect = "Send a HTTP GET request and check the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_cve_id("CVE-2014-2084");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
 script_version ("$Revision: 2780 $");

 script_name("Skybox Security Appliance Multiple Information Disclosure Vulnerabilities");


 script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33327/");
 
 script_tag(name:"last_modification", value:"$Date: 2016-03-04 14:12:04 +0100 (Fri, 04 Mar 2016) $");
 script_tag(name:"creation_date", value:"2014-05-13 16:33:50 +0200 (Tue, 13 May 2014)");
 script_summary("Determine if t is possible to access the admin without authentication.");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 444);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
  
port = get_http_port( default:444 );
if( ! get_port_state( port ) ) exit( 0 );

if( buf = http_vuln_check( port:port, url:'/', pattern:"<title>SkyBox Web Administration" ) )
{
  cookie = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );
  if( ! isnull( cookie[1] ) ) co = cookie[1];

  urls = make_array( "/scripts/commands/getSystemInformation?_=111111111","APPLIANCE_VERSION",
                     "/scripts/commands/getNetworkConfigurationInfo","HardwareAddress");     

  foreach url ( keys( urls ) )
  {
    if( http_vuln_check( port:port, url:url, pattern:urls[url], cookie:co ) )
    {
      security_message(port:port);
      exit( 0 );
    }
  }

  exit( 99 );

}

exit(0);


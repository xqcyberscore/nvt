###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_Meteo_Ad_pas_Ex.nasl 3425 2016-06-03 06:11:24Z mwiegand $
#
# Meteocontrol WEB'log - Admin Password Disclosure Exploit
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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


tag_insight = "All Meteocontrol WEB'log application functionality, and configuration pages, 
including those accessible after administrative login, can be accessed without any authentication.";

tag_impact = "Sensitive information can be accessed, and admin login pages are accessible without being authenticated.";

tag_affected = "All Meteocontrol's WEB'log versions / flavors have the same underlying design and are vulnerable..";

tag_summary = "Detection of Meteocontrol WEB'log - Admin Password Disclosure Exploit. The script tells if the 
Meteocontrol WEB'log  is vulnerable to Meteocontrol WEB'log Admin Password Disclosure Exploit";

tag_solution = "Ask the Vendor for an update.";

CPE ='cpe:/a:meteocontrol:weblog';

if (description)
{

 script_oid("1.3.6.1.4.1.25623.1.0.107003");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2016-2296");
 script_version("$Revision: 3425 $");
 script_tag(name:"last_modification", value:"$Date: 2016-06-03 08:11:24 +0200 (Fri, 03 Jun 2016) $");
 script_tag(name:"creation_date", value:"2016-05-20 10:42:39 +0100 (Fri, 20 May 2016)");
 script_tag(name:"qod_type", value:"exploit");
 script_name("Meteocontrol WEB'log - Admin Password Disclosure Exploit");
 script_summary("Checks for the presence Meteocontrol WEB'log  and tell wether it is vulnerable to Admin Password Disclosure Exploit");
 script_xref(name:"URL", value:"http://ipositivesecurity.blogspot.in/2016/05/ics-meteocontrol-weblog-security.html");
 script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-133-01");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_tag(name: "impact",    value: tag_impact);
 script_tag(name: "affected",  value: tag_affected);
 script_tag(name: "summary",   value: tag_summary);
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("gb_Meteocontrol_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Meteocontrol/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(port = get_app_port( cpe:CPE)) 
{
 url = '/html/en/confAccessProt.html';
 req = http_get( item:url, port:port );
 buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  
 if(buf =~ "HTTP/1\.. 200" && (buf =~ "szWebAdminPassword"  || buf =~ "/Admin Monitoring/") )
 {
	      pass = eregmatch(string: buf, pattern:'"szWebAdminPassword" value="([^"]+)" ', icase:TRUE);
	      if (! isnull( pass))
	      {	
	      	password= pass[1];
		if (password=='ist02')
	        {
			 report = 'The admin password "i***2" is default, change to another password. \nThe Meteocontrol WEB\'log version is vulnerable to Admin Password Disclosure Exploit, to fix it, download the last update at http://us.meteocontrol.com/downloads/';

	        }
	        else
	        {
		         report = 'The admin password "' +  password[0] + crap(data:"*", length:strlen(password) -2) + password[strlen(password)-2] + '" is disclosable ' + '.The Meteocontrol WEB\'log version is vulnerable to Admin Password Disclosure Exploit, to fix it, download the last update at http://us.meteocontrol.com/downloads/';
                }
	
	        security_message( port:port, data:report );
	        exit(0);
               }
 }

}
exit( 0 );


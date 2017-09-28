###############################################################################
# OpenVAS Vulnerability Test
# $Id: owa_sqlinject.nasl 7273 2017-09-26 11:17:25Z cfischer $
#
# Outlook Web Access URL Injection
#
# Authors:
# Michael J. Richardson <michael.richardson@protiviti.com>
#
# Copyright:
# Copyright (C) 2005 Michael J. Richardson
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# Vulnerability identified by Donnie Werner of Exploitlabs Research Team

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17636");
  script_version("$Revision: 7273 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-26 13:17:25 +0200 (Tue, 26 Sep 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-0420");
  script_bugtraq_id(12459);
  script_name("Outlook Web Access URL Injection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michael J. Richardson");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/36079/Exploit-Labs-Security-Advisory-2005.1.html");

  tag_summary = "The remote web server is vulnerable to a URL injection vulnerability.

  Description :

  The remote host is running Microsoft Outlook Web Access 2003.

  Due to a lack of sanitization of the user input, the remote version of this 
  software is vulnerable to URL injection which can be exploited to redirect a 
  user to a different, unauthorized web server after authenticating to OWA.  
  This unauthorized site could be used to capture sensitive information by 
  appearing to be part of the web application.";

  tag_solution = "None at this time";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

req = http_get(item:string("/exchweb/bin/auth/owalogon.asp?url=http://12345678910"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) exit(0);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) &&  
   "owaauth.dll" >< res && 
   '<INPUT type="hidden" name="destination" value="http://12345678910">' >< res)
  {
    security_message(port);
    exit(0);
  }

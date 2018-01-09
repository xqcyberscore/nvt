###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpbb_unspecified_vuln.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# phpBB 'posting.php' Unspecified Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "It has unknown impact and attack vectors.
  Impact Level: Application";
tag_affected = "phpBB version before 3.0.5";
tag_insight = "The flaw is due to unspecified error in 'posting.php', which has
  unknown impact and attack vectors related to the use of a 'forum id'.";
tag_solution = "Upgrade phpBB to 3.0.5 later,
  For updates refer to http://www.phpbb.com/downloads/";
tag_summary = "This host is running phpBB and is prone to unspecified
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902181");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1630");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpBB 'posting.php' Unspecified Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/05/16/1");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/05/19/5");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/05/18/12");
  script_xref(name : "URL" , value : "http://www.phpbb.com/community/viewtopic.php?f=14&p=9764445");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

phpBBPort = get_http_port(default:80);
if(!phpBBPort){
  exit(0);
}

phpBBVer = get_kb_item(string("www/", phpBBPort, "/phpBB"));
if(isnull(phpBBVer)){
  exit(0);
}

phpBBVer = eregmatch(pattern:"^(.+) under (/.*)$", string:phpBBVer);
if(!isnull(phpBBVer[1]))
{
  pBBVer = ereg_replace(pattern:"-", replace:".", string:phpBBVer[1]);

  # Check for phpBB Version < 3.0.5
  if(isnull(pBBVer))
  {
    if(version_is_less(version:pBBVer, test_version:"3.0.5")){
      security_message(phpBBPort);
    }
  }
}

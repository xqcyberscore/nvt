###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mrbs_sql_inj_vuln.nasl 4869 2016-12-29 11:01:45Z teissa $
#
# Meeting Room Booking System SQL Injection Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Attackers can exploit this issue to inject arbitrary SQL code and modify
  information in the back-end database.
  Impact Level: Application.";
tag_affected = "Meeting Room Booking System prior to 1.4.2 on all platforms.";
tag_insight = "The user supplied data passed into 'typematch' parameter in report.php is
  not properly sanitised before being used in an SQL query.";
tag_solution = "Upgrade to Meeting Room Booking System 1.4.2 or later.
  For updates refer to http://mrbs.sourceforge.net/download.php";
tag_summary = "This host is installed with Meeting Room Booking System and is
  prone to SQL Injection vulnerability.";

if(description)
{
  script_id(800950);
  script_version("$Revision: 4869 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 12:01:45 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3533");
  script_name("Meeting Room Booking System SQL Injection Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mrbs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35469");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51772");
  script_xref(name : "URL" , value : "http://mrbs.sourceforge.net/view_text.php?section=NEWS&file=NEWS");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

mrbsPort = get_http_port(default:80);

if(!mrbsPort){
  exit(0);
}

mrbsVer = get_kb_item("www/" + mrbsPort + "/MRBS");
mrbsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:mrbsVer);

if(mrbsVer[1] != NULL)
{
  if(version_is_less(version:mrbsVer[1], test_version:"1.4.2")){
    security_message(mrbsPort);
  }
}

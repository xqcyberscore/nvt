###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2mc_mult_unspecified_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# DB2 Monitoring Console Multiple Unspecified Security Bypass Vulnerabilities
#
# Authors:
# Antu Sanadi<santu@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to bypass certain
  security restrictions or potentially compromise a vulnerable system.
  Impact Level: System/Application.";
tag_affected = "DB2 Monitoring Console Version 2.2.24 and prior.";
tag_insight = "- An unspecified error can be exploited to upload files to the web
    server hosting the application.
  - An unspecified error can be exploited to gain access to the database
    that a user is currently connected to by tricking the user to access
    malicious link.";
tag_solution = "Upgrade to DB2 Monitoring Console Version 2.2.25 or later.
  For updates refer to http://sourceforge.net/projects/db2mc/files/";
tag_summary = "The host is running IBM DMC and is prone to multiple
  Unspecified Security Bypass Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800691");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7130", "CVE-2008-7131");
  script_bugtraq_id(28253);
  script_name("DB2 Monitoring Console Multiple Unspecified Security Bypass Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/29367");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/384393.php");
  script_xref(name : "URL" , value : "http://sourceforge.net/forum/forum.php?forum_id=797405");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_db2mc_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

dmcPort = get_http_port(default:80);
if(!dmcPort)
{
  exit(0);
}

dmcVer = get_kb_item("www/" + dmcPort + "/IBM/DB2MC");
if(!dmcVer)
{
   exit(0);
}

dmcVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dmcVer);
if(dmcVer[1] != NULL)
{
  if(version_is_less_equal(version:dmcVer[1], test_version:"2.2.24")){
    security_message(dmcPort);
  }
}
